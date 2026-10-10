//go:build with_quic

package snell

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type snellHTTP3TestDialer struct {
	N.Dialer
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d snellHTTP3TestDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

func newHTTP3LifecycleDialer(t *testing.T, happyEyeballs bool, dial func(context.Context, string, M.Socksaddr) (net.Conn, error)) *http3Dialer {
	t.Helper()
	generation, cancel := context.WithCancel(context.Background())
	d := &http3Dialer{
		Dialer: snellHTTP3TestDialer{dial: dial},
		ctx:    context.Background(), generation: generation, cancel: cancel,
		options:   option.SnellTransportOptions{HappyEyeballs: happyEyeballs},
		tlsConfig: &http3TLSConfig{snapshot: &boxTLS.STDConfig{}},
		sessions:  make(map[*http3Session]struct{}),
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestSnellHTTP3BlackholeCooldown(t *testing.T) {
	for _, tcpFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP wins", true: "TCP fails"}[tcpFails], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var h3Starts, tcpStarts atomic.Int32
				tcpErr := errors.New("TCP unavailable")
				d := newHTTP3LifecycleDialer(t, true, func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
					h3Starts.Add(1)
					<-ctx.Done()
					return nil, ctx.Err()
				})
				var tcpAt time.Time
				d.tcp = snellHTTP3TestDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
					tcpAt = time.Now()
					tcpStarts.Add(1)
					if tcpFails {
						return nil, tcpErr
					}
					return new(snellRaceConn), nil
				}}
				start := time.Now()
				c, err := d.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
				require.Equal(t, 250*time.Millisecond, tcpAt.Sub(start))
				if tcpFails {
					require.ErrorIs(t, err, tcpErr)
					require.ErrorIs(t, err, context.DeadlineExceeded)
					require.Equal(t, 2*time.Second, time.Since(start))
				} else {
					require.NoError(t, err)
					require.Equal(t, 250*time.Millisecond, time.Since(start))
					c.Close()
					time.Sleep(2 * time.Second)
				}
				synctest.Wait()
				d.mu.Lock()
				retryAfter := d.retryAfter
				d.mu.Unlock()
				require.Equal(t, start.Add(32*time.Second), retryAfter)
				before := time.Now()
				c, err = d.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
				require.Equal(t, tcpFails, err != nil)
				require.Equal(t, time.Duration(0), time.Since(before))
				require.EqualValues(t, 1, h3Starts.Load())
				require.EqualValues(t, 2, tcpStarts.Load())
				if c != nil {
					c.Close()
				}
				time.Sleep(time.Until(retryAfter))
				c, _ = d.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
				require.EqualValues(t, 2, h3Starts.Load(), "expired cooldown must retry H3")
				if c != nil {
					c.Close()
				}
				d.Close()
				synctest.Wait()
			})
		})
	}
}

func TestSnellHTTP3OnlyNeverStartsTCP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var tcpStarts atomic.Int32
		d := newHTTP3LifecycleDialer(t, false, func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		d.tcp = snellHTTP3TestDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			tcpStarts.Add(1)
			return new(snellRaceConn), nil
		}}
		start := time.Now()
		conn, err := d.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
		require.Nil(t, conn)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, 10*time.Second, time.Since(start))
		synctest.Wait()
		require.Zero(t, tcpStarts.Load())
		require.True(t, d.retryAfter.IsZero())
	})
}

func TestSnellHTTP3SharedDialFailsWaitersOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var dials atomic.Int32
		dialErr := errors.New("handshake failed")
		d := newHTTP3LifecycleDialer(t, true, func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
			if dials.Add(1) == 1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Second):
					return nil, dialErr
				}
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		initiator, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := d.get(initiator, d.generation)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		errs := make(chan error, 8)
		for range cap(errs) {
			go func() {
				_, err := d.get(context.Background(), d.generation)
				errs <- err
			}()
		}
		for range cap(errs) {
			require.ErrorIs(t, <-errs, dialErr)
		}
		require.EqualValues(t, 1, dials.Load())
		start := time.Now()
		_, err = d.get(context.Background(), d.generation)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, 2*time.Second, time.Since(start))
		require.EqualValues(t, 2, dials.Load())
	})
}

func TestSnellHTTP3ResetPreservesNewPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var dials atomic.Int32
		oldCanceled, releaseOld := make(chan struct{}), make(chan struct{})
		d := newHTTP3LifecycleDialer(t, true, func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
			if dials.Add(1) == 1 {
				<-ctx.Done()
				close(oldCanceled)
				<-releaseOld
			} else {
				<-ctx.Done()
			}
			return nil, ctx.Err()
		})
		oldGeneration := d.generation
		oldDone := make(chan error, 1)
		go func() {
			_, err := d.get(context.Background(), oldGeneration)
			oldDone <- err
		}()
		synctest.Wait()
		d.Reset()
		<-oldCanceled
		newGeneration := d.generation
		newDone := make(chan error, 1)
		go func() {
			_, err := d.get(context.Background(), newGeneration)
			newDone <- err
		}()
		synctest.Wait()
		d.mu.Lock()
		newPending := d.pending
		d.mu.Unlock()
		require.NotNil(t, newPending)
		close(releaseOld)
		require.Error(t, <-oldDone)
		synctest.Wait()
		d.mu.Lock()
		currentPending := d.pending
		d.mu.Unlock()
		require.Same(t, newPending, currentPending)
		d.recordHTTP3Result(newGeneration, false)
		retryAfter := d.retryAfter
		d.recordHTTP3Result(oldGeneration, true)
		require.Equal(t, retryAfter, d.retryAfter)
		d.Reset()
		d.recordHTTP3Result(oldGeneration, false)
		require.True(t, d.retryAfter.IsZero())
		require.Error(t, <-newDone)
		synctest.Wait()
		require.Nil(t, d.pending)
		require.Empty(t, d.sessions)
		require.EqualValues(t, 2, dials.Load())
	})
}

func TestSnellHTTP3LifecycleCancelsOrphanedProbe(t *testing.T) {
	for _, closeDialer := range []bool{false, true} {
		t.Run(map[bool]string{false: "reset", true: "close"}[closeDialer], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var exits atomic.Int32
				d := newHTTP3LifecycleDialer(t, true, func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
					<-ctx.Done()
					exits.Add(1)
					return nil, ctx.Err()
				})
				d.tcp = snellHTTP3TestDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
					return new(snellRaceConn), nil
				}}
				c, err := d.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
				require.NoError(t, err)
				c.Close()
				start := time.Now()
				oldGeneration := d.generation
				if closeDialer {
					d.Close()
				} else {
					d.Reset()
				}
				synctest.Wait()
				require.EqualValues(t, 1, exits.Load())
				require.Equal(t, time.Duration(0), time.Since(start))
				d.recordHTTP3Result(oldGeneration, false)
				require.True(t, d.retryAfter.IsZero())
				require.Nil(t, d.pending)
				require.Empty(t, d.sessions)
				if closeDialer {
					_, err = d.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
					require.ErrorIs(t, err, net.ErrClosed)
				}
			})
		})
	}
}

func TestSnellHTTP3SuccessClearsConcurrentFailure(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "H3 wins", true: "late H3"}[late], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newHTTP3LifecycleDialer(t, true, nil)
				generation := d.generation
				time.AfterFunc(100*time.Millisecond, func() { d.recordHTTP3Result(generation, false) })
				h3 := new(snellRaceConn)
				conn, err := raceSnellTransports(context.Background(), generation, 250*time.Millisecond, 2*time.Second,
					func(context.Context) (net.Conn, error) {
						if late {
							time.Sleep(time.Second)
						} else {
							time.Sleep(200 * time.Millisecond)
						}
						return h3, nil
					}, func(context.Context) (net.Conn, error) { return new(snellRaceConn), nil },
					func(ok bool) { d.recordHTTP3Result(generation, ok) })
				require.NoError(t, err)
				time.Sleep(time.Second)
				synctest.Wait()
				require.True(t, d.retryAfter.IsZero())
				require.Equal(t, late, h3.closes.Load() == 1)
				conn.Close()
			})
		})
	}
}

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

	"github.com/stretchr/testify/require"
)

type snellRaceConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *snellRaceConn) Close() error {
	c.closes.Add(1)
	return nil
}

func TestSnellHappyEyeballsTiming(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		h3Delay, tcpDelay, elapsed   time.Duration
		h3Fails, tcpFails            bool
		wantTCP, startTCP, h3Success bool
	}{
		{"fast H3", 100 * time.Millisecond, 0, 100 * time.Millisecond, false, false, false, false, true},
		{"blackholed H3", 5 * time.Second, 50 * time.Millisecond, 300 * time.Millisecond, false, false, true, true, false},
		{"early H3 failure", 20 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond, true, false, true, true, false},
		{"H3 wins overlap", 300 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond, false, false, false, true, true},
		{"TCP fails first", 400 * time.Millisecond, 10 * time.Millisecond, 400 * time.Millisecond, false, true, false, true, true},
		{"late H3 success", time.Second, 50 * time.Millisecond, 300 * time.Millisecond, false, false, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h3, tcp := new(snellRaceConn), new(snellRaceConn)
				var tcpStarts, successes, failures atomic.Int32
				dial := func(c net.Conn, delay time.Duration, fails bool) func(context.Context) (net.Conn, error) {
					return func(ctx context.Context) (net.Conn, error) {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case <-time.After(delay):
						}
						if fails {
							return nil, errors.New("unreachable")
						}
						return c, nil
					}
				}
				before := time.Now()
				got, err := raceSnellTransports(context.Background(), context.Background(), 250*time.Millisecond, 2*time.Second,
					dial(h3, tc.h3Delay, tc.h3Fails), func(ctx context.Context) (net.Conn, error) {
						tcpStarts.Add(1)
						return dial(tcp, tc.tcpDelay, tc.tcpFails)(ctx)
					}, func(ok bool) {
						if ok {
							successes.Add(1)
						} else {
							failures.Add(1)
						}
					})
				require.NoError(t, err)
				require.Equal(t, tc.wantTCP, got == tcp)
				require.Equal(t, tc.elapsed, time.Since(before))
				time.Sleep(2 * time.Second)
				synctest.Wait()
				require.Equal(t, tc.startTCP, tcpStarts.Load() == 1)
				require.EqualValues(t, 1, successes.Load()+failures.Load())
				require.Equal(t, tc.h3Success, successes.Load() == 1)
				require.Equal(t, tc.wantTCP && tc.h3Success, h3.closes.Load() == 1)
				require.Zero(t, tcp.closes.Load())
				require.NoError(t, got.Close())
			})
		})
	}
}

func TestSnellHTTP3Delay(t *testing.T) {
	for _, tc := range []struct{ rtt, want time.Duration }{
		{-time.Second, 250 * time.Millisecond},
		{0, 250 * time.Millisecond},
		{10 * time.Millisecond, 100 * time.Millisecond},
		{150 * time.Millisecond, 300 * time.Millisecond},
		{300 * time.Millisecond, 600 * time.Millisecond},
		{800 * time.Millisecond, time.Second},
	} {
		require.Equal(t, tc.want, snellHTTP3Delay(tc.rtt))
	}
}

func TestSnellHappyEyeballsCancellation(t *testing.T) {
	for _, after := range []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond} {
		t.Run(after.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if after == 0 {
					cancel()
				} else {
					time.AfterFunc(after, cancel)
				}
				var starts, exits, health atomic.Int32
				dial := func(ctx context.Context) (net.Conn, error) {
					starts.Add(1)
					<-ctx.Done()
					exits.Add(1)
					return nil, ctx.Err()
				}
				got, err := raceSnellTransports(ctx, context.Background(), 250*time.Millisecond, 2*time.Second,
					dial, dial, func(bool) { health.Add(1) })
				require.Nil(t, got)
				require.ErrorIs(t, err, context.Canceled)
				synctest.Wait()
				want := int32(0)
				if after > 0 {
					want++
				}
				if after >= 250*time.Millisecond {
					want++
				}
				require.Equal(t, want, starts.Load())
				require.Equal(t, want, exits.Load())
				require.Zero(t, health.Load())
			})
		})
	}
}

func TestSnellHappyEyeballsBothFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h3Err, tcpErr := errors.New("H3 unavailable"), errors.New("TCP unavailable")
		conn, err := raceSnellTransports(context.Background(), context.Background(), time.Second, 2*time.Second,
			func(context.Context) (net.Conn, error) { return nil, h3Err },
			func(context.Context) (net.Conn, error) { return nil, tcpErr }, func(bool) {})
		require.Nil(t, conn)
		require.ErrorIs(t, err, h3Err)
		require.ErrorIs(t, err, tcpErr)
		require.ErrorContains(t, err, "HTTP/3:")
		require.ErrorContains(t, err, "TCP:")
	})
}

func TestSnellHappyEyeballsClosesLateConnections(t *testing.T) {
	for _, cancelCaller := range []bool{false, true} {
		t.Run(map[bool]string{false: "H3 wins", true: "caller cancels"}[cancelCaller], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				h3, tcp := new(snellRaceConn), new(snellRaceConn)
				var health atomic.Int32
				if cancelCaller {
					time.AfterFunc(300*time.Millisecond, cancel)
				}
				got, err := raceSnellTransports(ctx, context.Background(), 250*time.Millisecond, 2*time.Second,
					func(ctx context.Context) (net.Conn, error) {
						if cancelCaller {
							<-ctx.Done()
						} else {
							time.Sleep(300 * time.Millisecond)
						}
						return h3, nil
					}, func(ctx context.Context) (net.Conn, error) {
						<-ctx.Done()
						return tcp, nil
					}, func(bool) { health.Add(1) })
				synctest.Wait()
				require.EqualValues(t, 1, tcp.closes.Load())
				if cancelCaller {
					require.Nil(t, got)
					require.ErrorIs(t, err, context.Canceled)
					require.EqualValues(t, 1, h3.closes.Load())
					require.Zero(t, health.Load())
				} else {
					require.NoError(t, err)
					require.Same(t, h3, got)
					require.Zero(t, h3.closes.Load())
					require.EqualValues(t, 1, health.Load())
					got.Close()
				}
			})
		})
	}
}

func TestSnellHappyEyeballsClosesConnectionsWithErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h3, tcp := new(snellRaceConn), new(snellRaceConn)
		_, err := raceSnellTransports(context.Background(), context.Background(), time.Second, 2*time.Second,
			func(context.Context) (net.Conn, error) { return h3, errors.New("H3 failure") },
			func(context.Context) (net.Conn, error) { return tcp, errors.New("TCP failure") }, func(bool) {})
		require.Error(t, err)
		synctest.Wait()
		require.EqualValues(t, 1, h3.closes.Load())
		require.EqualValues(t, 1, tcp.closes.Load())
	})
}

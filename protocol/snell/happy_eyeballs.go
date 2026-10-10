//go:build with_quic

package snell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

func snellHTTP3Delay(smoothedRTT time.Duration) time.Duration {
	if smoothedRTT <= 0 {
		return 250 * time.Millisecond
	}
	// A CONNECT on a live session takes one RTT; leave room for two.
	return min(max(2*smoothedRTT, 100*time.Millisecond), time.Second)
}

// Race verified transports before sending any Snell authentication or data.
// After TCP wins, H3 keeps probing within its budget, but never across a reset.
func raceSnellTransports(ctx, generation context.Context, delay, h3Timeout time.Duration,
	h3, tcp func(context.Context) (net.Conn, error), h3Finished func(bool),
) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h3Ctx, cancelH3 := context.WithTimeout(context.WithoutCancel(ctx), h3Timeout)
	followCaller := context.AfterFunc(ctx, cancelH3)
	followGeneration := context.AfterFunc(generation, cancelH3)
	var orphaned atomic.Bool
	type result struct {
		conn net.Conn
		err  error
		h3   bool
	}
	// The producer owns its connection until the receiver accepts it.
	results := make(chan result)
	start := func(isH3 bool, dialCtx context.Context, dial func(context.Context) (net.Conn, error)) {
		go func() {
			if isH3 {
				defer cancelH3()
				defer followCaller()
				defer followGeneration()
			}
			conn, err := dial(dialCtx)
			select {
			case results <- result{conn, err, isH3}:
			case <-ctx.Done():
				if isH3 && orphaned.Load() && generation.Err() == nil {
					h3Finished(err == nil)
				}
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	start(true, h3Ctx, h3)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	timerC := timer.C
	startTCP := func() {
		if timerC != nil {
			timer.Stop()
			timerC = nil
			start(false, ctx, tcp)
		}
	}
	var h3Err, tcpErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timerC:
			startTCP()
		case r := <-results:
			if err := ctx.Err(); err != nil {
				if r.conn != nil {
					r.conn.Close()
				}
				return nil, err
			}
			if r.err == nil {
				if r.h3 {
					h3Finished(true)
				} else if h3Err == nil {
					orphaned.Store(followCaller())
				}
				return r.conn, nil
			}
			if r.conn != nil {
				r.conn.Close()
			}
			if r.h3 {
				h3Err = r.err
				h3Finished(false)
				startTCP()
			} else {
				tcpErr = r.err
			}
			if h3Err != nil && tcpErr != nil {
				return nil, errors.Join(fmt.Errorf("HTTP/3: %w", h3Err), fmt.Errorf("TCP: %w", tcpErr))
			}
		}
	}
}

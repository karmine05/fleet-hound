package graphdb

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func neoErr(err error) *neo4j.Neo4jError {
	var ne *neo4j.Neo4jError
	if errors.As(err, &ne) {
		return ne
	}
	return nil
}

// IsClientError matches python neo4j.exceptions.ClientError: a server error
// whose code classification is "ClientError" (e.g. bad Cypher, invalid regex).
// Memgraph codes look like "Memgraph.ClientError.MemgraphError.MemgraphError".
func IsClientError(err error) bool {
	ne := neoErr(err)
	return ne != nil && ne.Classification() == "ClientError"
}

// IsTransient matches python TransientError (classification "TransientError",
// e.g. Memgraph serialization conflicts). Safe to retry.
func IsTransient(err error) bool {
	ne := neoErr(err)
	return ne != nil && ne.Classification() == "TransientError"
}

// IsAuthError matches python AuthError (security failures at connect).
func IsAuthError(err error) bool {
	ne := neoErr(err)
	if ne == nil {
		return false
	}
	return ne.Category() == "Security" || ne.Title() == "Unauthorized" ||
		ne.Title() == "Unauthenticated"
}

// IsServiceUnavailable matches python ServiceUnavailable and SessionExpired:
// connectivity failures and the "driver not connected" sentinel.
func IsServiceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrUnavailable) || neo4j.IsConnectivityError(err)
}

// IsRetryable is IsTransient || IsServiceUnavailable (the set
// categorize_software.run_query_with_retry retries).
func IsRetryable(err error) bool {
	return IsTransient(err) || IsServiceUnavailable(err) || neo4j.IsRetryable(err)
}

// Retry calls fn up to attempts times while retryable(err) is true, sleeping
// base*2^i between tries; with jitter the sleep is uniform in [0, base*2^i]
// (ingestion._execute_with_retry), otherwise exact (run_query_with_retry).
// It stops early on ctx cancellation and returns the last error.
func Retry(ctx context.Context, attempts int, base time.Duration, jitter bool,
	retryable func(error) bool, fn func(context.Context) error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(ctx); err == nil || !retryable(err) {
			return err
		}
		if i == attempts-1 {
			break
		}
		d := base << i
		if jitter && d > 0 {
			d = time.Duration(rand.Int64N(int64(d) + 1)) // #nosec G404 -- retry backoff jitter, not security
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(d):
		}
	}
	return err
}

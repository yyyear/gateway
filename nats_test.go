package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/yyyear/RouterModel"
)

func TestHeartbeatStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go heartbeat(ctx, nil, &RouterModel.Router{Name: "test"}, done)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not stop after context cancellation")
	}
}

func TestParseRouterIndex(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "numeric ID", raw: `7`, want: "7"},
		{name: "string ID", raw: `"8"`, want: "8"},
		{name: "invalid ID", raw: `"gateway-a"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRouterIndex(json.RawMessage(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseRouterIndex() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseRouterIndex() = %q, want %q", got, tt.want)
			}
		})
	}
}

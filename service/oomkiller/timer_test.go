package oomkiller

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestNetworkExtensionDefaultPollInterval(t *testing.T) {
	config, err := buildTimerConfig(option.OOMKillerServiceOptions{}, DefaultAppleNetworkExtensionMemoryLimit, policyModeNetworkExtension, false)
	if err != nil {
		t.Fatal(err)
	}
	if config.minInterval != 100*time.Millisecond || config.maxInterval != time.Second {
		t.Fatalf("network extension polling interval = %s..%s, want 100ms..1s", config.minInterval, config.maxInterval)
	}
	thresholds := computeLimitThresholds(config.memoryLimit, config.safetyMargin)
	if thresholds.armed != 40*1024*1024 || thresholds.trigger != 45*1024*1024 || thresholds.resume != 30*1024*1024 {
		t.Fatalf("network extension memory safety margins changed: %+v", thresholds)
	}
}

func TestOtherDefaultPollIntervalsUnchanged(t *testing.T) {
	for _, mode := range []policyMode{policyModeNone, policyModeMemoryLimit, policyModeAvailable} {
		config, err := buildTimerConfig(option.OOMKillerServiceOptions{}, DefaultAppleNetworkExtensionMemoryLimit, mode, false)
		if err != nil {
			t.Fatal(err)
		}
		if config.maxInterval != 10*time.Second {
			t.Fatalf("%s default polling interval changed to %s", mode, config.maxInterval)
		}
	}
}

func TestNetworkExtensionExplicitPollIntervalRetained(t *testing.T) {
	options := option.OOMKillerServiceOptions{MaxInterval: badoption.Duration(2 * time.Second)}
	config, err := buildTimerConfig(options, DefaultAppleNetworkExtensionMemoryLimit, policyModeNetworkExtension, false)
	if err != nil {
		t.Fatal(err)
	}
	if config.maxInterval != 2*time.Second {
		t.Fatalf("explicit polling interval changed to %s", config.maxInterval)
	}
}

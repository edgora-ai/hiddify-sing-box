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

func TestNetworkExtensionMinOnlyPollIntervalRetained(t *testing.T) {
	options := option.OOMKillerServiceOptions{MinInterval: badoption.Duration(2 * time.Second)}
	config, err := buildTimerConfig(options, DefaultAppleNetworkExtensionMemoryLimit, policyModeNetworkExtension, false)
	if err != nil {
		t.Fatal(err)
	}
	if config.minInterval != 2*time.Second || config.maxInterval != 2*time.Second || config.armedInterval != 2*time.Second {
		t.Fatalf("min-only network extension intervals = %s/%s/%s, want 2s/2s/2s", config.minInterval, config.armedInterval, config.maxInterval)
	}
}

func TestOtherMinOnlyPollIntervalsUnchanged(t *testing.T) {
	for _, mode := range []policyMode{policyModeNone, policyModeMemoryLimit, policyModeAvailable} {
		t.Run(mode.String(), func(t *testing.T) {
			options := option.OOMKillerServiceOptions{MinInterval: badoption.Duration(2 * time.Second)}
			config, err := buildTimerConfig(options, DefaultAppleNetworkExtensionMemoryLimit, mode, false)
			if err != nil {
				t.Fatal(err)
			}
			if config.minInterval != 2*time.Second || config.maxInterval != 10*time.Second || config.armedInterval != 2*time.Second {
				t.Fatalf("min-only intervals = %s/%s/%s, want 2s/2s/10s", config.minInterval, config.armedInterval, config.maxInterval)
			}
			options.MinInterval = badoption.Duration(11 * time.Second)
			if _, err := buildTimerConfig(options, DefaultAppleNetworkExtensionMemoryLimit, mode, false); err == nil {
				t.Fatal("min_interval above the non-NE default maximum was accepted")
			}
		})
	}
}

func TestExplicitPollIntervalBoundsRejectReversed(t *testing.T) {
	for _, mode := range []policyMode{policyModeNetworkExtension, policyModeNone, policyModeMemoryLimit, policyModeAvailable} {
		t.Run(mode.String(), func(t *testing.T) {
			options := option.OOMKillerServiceOptions{
				MinInterval: badoption.Duration(2 * time.Second),
				MaxInterval: badoption.Duration(time.Second),
			}
			if _, err := buildTimerConfig(options, DefaultAppleNetworkExtensionMemoryLimit, mode, false); err == nil {
				t.Fatal("explicit max_interval below min_interval was accepted")
			}
			options.MaxInterval = badoption.Duration(2 * time.Second)
			config, err := buildTimerConfig(options, DefaultAppleNetworkExtensionMemoryLimit, mode, false)
			if err != nil {
				t.Fatal(err)
			}
			if config.minInterval != 2*time.Second || config.maxInterval != 2*time.Second {
				t.Fatalf("equal explicit interval bounds changed to %s..%s", config.minInterval, config.maxInterval)
			}
		})
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

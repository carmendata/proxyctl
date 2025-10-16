package main

import (
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "less than a minute",
			duration: 30 * time.Second,
			expected: "30 seconds",
		},
		{
			name:     "exactly one minute",
			duration: 1 * time.Minute,
			expected: "1 minutes",
		},
		{
			name:     "several minutes",
			duration: 15 * time.Minute,
			expected: "15 minutes",
		},
		{
			name:     "less than one hour",
			duration: 45 * time.Minute,
			expected: "45 minutes",
		},
		{
			name:     "exactly one hour",
			duration: 1 * time.Hour,
			expected: "1 hours",
		},
		{
			name:     "several hours",
			duration: 5 * time.Hour,
			expected: "5 hours",
		},
		{
			name:     "less than 24 hours",
			duration: 23 * time.Hour,
			expected: "23 hours",
		},
		{
			name:     "exactly one day",
			duration: 24 * time.Hour,
			expected: "1 day",
		},
		{
			name:     "several days",
			duration: 5 * 24 * time.Hour,
			expected: "5 days",
		},
		{
			name:     "more than a week",
			duration: 10 * 24 * time.Hour,
			expected: "10 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, result, tt.expected)
			}
		})
	}
}

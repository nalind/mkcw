package mkcw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlop(t *testing.T) {
	testCases := []struct {
		input  int64
		slop   string
		output int64
	}{
		{100, "", 125},
		{100, "10%", 110},
		{100, "100%", 200},
		{100, "10GB", 10*1024*1024*1024 + 100},
	}
	for _, testCase := range testCases {
		t.Run(testCase.slop, func(t *testing.T) {
			assert.Equal(t, testCase.output, slop(testCase.input, testCase.slop))
		})
	}
}

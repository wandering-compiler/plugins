package payment

import "testing"

func TestProbeMustFailCI(t *testing.T) { t.Fatal("deliberate: CI must go red") }

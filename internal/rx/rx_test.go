package rx

import "testing"

func TestCompileRemembers(t *testing.T) {
	a, err := Compile(`(?i)prod`)
	b, _ := Compile(`(?i)prod`)
	if err != nil || a != b || !a.MatchString("PROD") {
		t.Fatalf("a=%p b=%p err=%v", a, b, err)
	}
	if _, err := Compile(`(`); err == nil {
		t.Fatal("a bad pattern must still fail")
	}
	if _, err := Compile(`(`); err == nil {
		t.Fatal("…every time")
	}
}

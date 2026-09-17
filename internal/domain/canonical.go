package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// CanonicalJSON implements the restricted I-JSON subset GAR uses for authority
// digests. Authority-bearing models intentionally contain no floating-point
// values; accepting one would make cross-language canonicalization ambiguous.
func CanonicalJSON(value any) ([]byte, error) {
	if err := rejectFloats(reflect.ValueOf(value)); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(payload)
}

func Digest(value any) (string, error) {
	payload, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func NewID(prefix string) string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		panic(fmt.Sprintf("secure id generation failed: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(random)
}

func SortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func rejectFloats(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return rejectFloats(value.Elem())
	}
	switch value.Kind() {
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("authority payload cannot contain floating-point values")
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if err := rejectFloats(iterator.Value()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := rejectFloats(value.Index(index)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if value.Type().Field(index).PkgPath != "" {
				continue
			}
			if err := rejectFloats(value.Field(index)); err != nil {
				return err
			}
		}
	}
	return nil
}

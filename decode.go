package natsauth

import (
	"reflect"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

// mapstructureDurationHook lets Viper decode "1h", "30m" strings into
// time.Duration fields. Without this, Unmarshal chokes on duration fields
// coming from env vars (which are always strings).
func mapstructureDurationHook() mapstructure.DecodeHookFuncType {
	return func(_ reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf(time.Duration(0)) {
			return data, nil
		}
		switch v := data.(type) {
		case string:
			return time.ParseDuration(v)
		case int64:
			// If someone passes raw nanoseconds (unlikely but safe)
			return time.Duration(v), nil
		default:
			return data, nil
		}
	}
}

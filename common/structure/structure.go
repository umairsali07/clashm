package structure

// references: https://github.com/mitchellh/mapstructure

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/umairsali07/clashm/common/errors2"
)

var durationType = reflect.TypeOf(time.Duration(0))

// Option is the configuration that is used to create a new decoder
type Option struct {
	TagName          string
	WeaklyTypedInput bool
}

// Decoder is the core of structure
type Decoder struct {
	option *Option
}

// NewDecoder return a Decoder by Option
func NewDecoder(option Option) *Decoder {
	if option.TagName == "" {
		option.TagName = "structure"
	}
	return &Decoder{option: &option}
}

// Decode transform a map[string]any to a struct
func (d *Decoder) Decode(src map[string]any, dst any) error {
	if reflect.TypeOf(dst).Kind() != reflect.Ptr {
		return fmt.Errorf("decode must recive a ptr struct")
	}
	t := reflect.TypeOf(dst).Elem()
	v := reflect.ValueOf(dst).Elem()
	for idx := 0; idx < v.NumField(); idx++ {
		field := t.Field(idx)
		if field.Anonymous {
			if err := d.decodeStruct(field.Name, src, v.Field(idx)); err != nil {
				return err
			}
			continue
		}

		tag := field.Tag.Get(d.option.TagName)
		key, omitKey, found := strings.Cut(tag, ",")
		omitempty := found && omitKey == "omitempty"

		value, ok := src[key]
		if !ok || value == nil {
			if omitempty {
				continue
			}
			return fmt.Errorf("key '%s' missing", key)
		}

		err := d.decode(key, value, v.Field(idx))
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Decoder) decode(name string, data any, val reflect.Value) error {
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return d.decodeInt(name, data, val)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return d.decodeUint(name, data, val)
	case reflect.String:
		return d.decodeString(name, data, val)
	case reflect.Bool:
		return d.decodeBool(name, data, val)
	case reflect.Slice:
		return d.decodeSlice(name, data, val)
	case reflect.Map:
		return d.decodeMap(name, data, val)
	case reflect.Interface:
		return d.setInterface(name, data, val)
	case reflect.Struct:
		return d.decodeStruct(name, data, val)
	default:
		return fmt.Errorf("type %s not support", val.Kind().String())
	}
}

func (d *Decoder) decodeInt(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	switch {
	case dataVal.CanInt():
		resolved := dataVal.Int()
		if val.Type() == durationType {
			resolved *= 1e9
		}
		val.SetInt(resolved)
	case dataVal.CanUint():
		resolved := dataVal.Uint()
		if val.Type() == durationType {
			resolved *= 1e9
		}
		val.SetInt(int64(resolved))
	case dataVal.CanFloat() && d.option.WeaklyTypedInput:
		resolved := dataVal.Float()
		if val.Type() == durationType {
			resolved *= 1e9
		}
		val.SetInt(int64(resolved))
	case dataVal.Kind() == reflect.String && d.option.WeaklyTypedInput:
		var (
			rs       int64
			valType  = val.Type()
			resolved = dataVal.String()
		)

		rs, err = strconv.ParseInt(resolved, 0, valType.Bits())
		if err == nil {
			if valType == durationType {
				rs *= 1e9
			}
			val.SetInt(rs)
		} else if valType == durationType {
			dur, err1 := time.ParseDuration(resolved)
			if err1 == nil {
				val.SetInt(int64(dur))
			}
			err = err1
		}

		if err != nil {
			err = fmt.Errorf("cannot parse '%s' as int: %w", name, err)
		}
	default:
		err = fmt.Errorf(
			"'%s' expected type '%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeUint(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	switch {
	case dataVal.CanInt():
		val.SetUint(uint64(dataVal.Int()))
	case dataVal.CanUint():
		val.SetUint(dataVal.Uint())
	case dataVal.CanFloat() && d.option.WeaklyTypedInput:
		val.SetUint(uint64(dataVal.Float()))
	case dataVal.Kind() == reflect.String && d.option.WeaklyTypedInput:
		var i uint64
		i, err = strconv.ParseUint(dataVal.String(), 0, val.Type().Bits())
		if err == nil {
			val.SetUint(i)
		} else {
			err = fmt.Errorf("cannot parse '%s' as uint: %w", name, err)
		}
	default:
		err = fmt.Errorf(
			"'%s' expected type '%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeString(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case kind == reflect.String:
		val.SetString(dataVal.String())
	case kind == reflect.Bool && d.option.WeaklyTypedInput:
		val.SetString(strconv.FormatBool(dataVal.Bool()))
	case dataVal.CanInt() && d.option.WeaklyTypedInput:
		val.SetString(strconv.FormatInt(dataVal.Int(), 10))
	default:
		err = fmt.Errorf(
			"'%s' expected type '%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeBool(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case kind == reflect.Bool:
		val.SetBool(dataVal.Bool())
	case dataVal.CanInt() && d.option.WeaklyTypedInput:
		val.SetBool(dataVal.Int() != 0)
	case kind == reflect.String && d.option.WeaklyTypedInput:
		v, _ := strconv.ParseBool(dataVal.String())
		val.SetBool(v)
	default:
		err = fmt.Errorf(
			"'%s' expected type '%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeSlice(name string, data any, val reflect.Value) error {
	dataVal := reflect.Indirect(reflect.ValueOf(data))
	valType := val.Type()
	valElemType := valType.Elem()

	if dataVal.Kind() != reflect.Slice {
		return fmt.Errorf("'%s' is not a slice", name)
	}

	valSlice := val
	for i := 0; i < dataVal.Len(); i++ {
		currentData := dataVal.Index(i).Interface()
		for valSlice.Len() <= i {
			valSlice = reflect.Append(valSlice, reflect.Zero(valElemType))
		}
		fieldName := fmt.Sprintf("%s[%d]", name, i)
		if currentData == nil {
			// in weakly type mode, null will convert to zero value
			if d.option.WeaklyTypedInput {
				continue
			}
			// in non-weakly type mode, null will convert to nil if element's zero value is nil
			// otherwise return an error
			if elemKind := valElemType.Kind(); elemKind == reflect.Map || elemKind == reflect.Slice {
				continue
			}
			return fmt.Errorf("'%s' can not be null", fieldName)
		}
		currentField := valSlice.Index(i)
		if err := d.decode(fieldName, currentData, currentField); err != nil {
			return err
		}
	}

	val.Set(valSlice)
	return nil
}

func (d *Decoder) decodeMap(name string, data any, val reflect.Value) error {
	valType := val.Type()
	valKeyType := valType.Key()
	valElemType := valType.Elem()

	valMap := val

	if valMap.IsNil() {
		mapType := reflect.MapOf(valKeyType, valElemType)
		valMap = reflect.MakeMap(mapType)
	}

	dataVal := reflect.Indirect(reflect.ValueOf(data))
	if dataVal.Kind() != reflect.Map {
		return fmt.Errorf("'%s' expected a map, got '%s'", name, dataVal.Kind())
	}

	return d.decodeMapFromMap(name, dataVal, val, valMap)
}

func (d *Decoder) decodeMapFromMap(name string, dataVal reflect.Value, val reflect.Value, valMap reflect.Value) error {
	valType := val.Type()
	valKeyType := valType.Key()
	valElemType := valType.Elem()

	if dataVal.Len() == 0 {
		if dataVal.IsNil() {
			if !val.IsNil() {
				val.Set(dataVal)
			}
		} else {
			val.Set(valMap)
		}

		return nil
	}

	var errs error
	for _, k := range dataVal.MapKeys() {
		fieldName := fmt.Sprintf("%s[%s]", name, k)

		currentKey := reflect.Indirect(reflect.New(valKeyType))
		if err := d.decode(fieldName, k.Interface(), currentKey); err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		v := dataVal.MapIndex(k).Interface()
		if v == nil {
			errs = errors.Join(errs, fmt.Errorf("filed %s invalid", fieldName))
			continue
		}

		currentVal := reflect.Indirect(reflect.New(valElemType))
		if err := d.decode(fieldName, v, currentVal); err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		valMap.SetMapIndex(currentKey, currentVal)
	}

	val.Set(valMap)

	if errs != nil {
		return errors2.New(errs)
	}

	return nil
}

func (d *Decoder) decodeStruct(name string, data any, val reflect.Value) error {
	dataVal := reflect.Indirect(reflect.ValueOf(data))

	// If the type of the value to write to and the data match directly,
	// then we just set it directly instead of recursing into the structure.
	if dataVal.Type() == val.Type() {
		val.Set(dataVal)
		return nil
	}

	dataValKind := dataVal.Kind()
	switch dataValKind {
	case reflect.Map:
		return d.decodeStructFromMap(name, dataVal, val)
	default:
		return fmt.Errorf("'%s' expected a map, got '%s'", name, dataVal.Kind())
	}
}

func (d *Decoder) decodeStructFromMap(name string, dataVal, val reflect.Value) error {
	dataValType := dataVal.Type()
	if kind := dataValType.Key().Kind(); kind != reflect.String && kind != reflect.Interface {
		return fmt.Errorf(
			"'%s' needs a map with string keys, has '%s' keys",
			name, dataValType.Key().Kind())
	}

	dataValKeys := make(map[reflect.Value]struct{})
	dataValKeysUnused := make(map[any]struct{})
	for _, dataValKey := range dataVal.MapKeys() {
		dataValKeys[dataValKey] = struct{}{}
		dataValKeysUnused[dataValKey.Interface()] = struct{}{}
	}

	// This slice will keep track of all the structs we'll be decoding.
	// There can be more than one struct if there are embedded structs
	// that are squashed.
	structs := make([]reflect.Value, 1, 5)
	structs[0] = val

	// Compile the list of all the fields that we're going to be decoding
	// from all the structs.
	type field struct {
		field reflect.StructField
		val   reflect.Value
	}

	var (
		fields []field
		errs   error
	)
	for len(structs) > 0 {
		structVal := structs[0]
		structs = structs[1:]

		structType := structVal.Type()

		for i := 0; i < structType.NumField(); i++ {
			fieldType := structType.Field(i)
			fieldKind := fieldType.Type.Kind()

			// If "squash" is specified in the tag, we squash the field down.
			squash := false
			tagParts := strings.Split(fieldType.Tag.Get(d.option.TagName), ",")
			for _, tag := range tagParts[1:] {
				if tag == "squash" {
					squash = true
					break
				}
			}

			if squash {
				if fieldKind != reflect.Struct {
					errs = errors.Join(
						errs,
						fmt.Errorf("%s: unsupported type for squash: %s", fieldType.Name, fieldKind),
					)
				} else {
					structs = append(structs, structVal.FieldByName(fieldType.Name))
				}
				continue
			}

			// Normal struct field, store it away
			fields = append(fields, field{fieldType, structVal.Field(i)})
		}
	}

	// for fieldType, field := range fields {
	for _, f := range fields {
		fieldM, fieldValue := f.field, f.val
		fieldName := fieldM.Name

		tagValue := fieldM.Tag.Get(d.option.TagName)
		tagValue = strings.SplitN(tagValue, ",", 2)[0]
		if tagValue != "" {
			fieldName = tagValue
		}

		rawMapKey := reflect.ValueOf(fieldName)
		rawMapVal := dataVal.MapIndex(rawMapKey)
		if !rawMapVal.IsValid() {
			// Do a slower search by iterating over each key and
			// doing case-insensitive search.
			for dataValKey := range dataValKeys {
				mK, ok := dataValKey.Interface().(string)
				if !ok {
					// Not a string key
					continue
				}

				if strings.EqualFold(mK, fieldName) {
					rawMapKey = dataValKey
					rawMapVal = dataVal.MapIndex(dataValKey)
					break
				}
			}

			if !rawMapVal.IsValid() {
				// There was no matching key in the map for the value in
				// the struct. Just ignore.
				continue
			}
		}

		// Delete the key we're using from the unused map so stop tracking
		delete(dataValKeysUnused, rawMapKey.Interface())

		if !fieldValue.IsValid() {
			// This should never happen
			panic("field is not valid")
		}

		// If we can't set the field, then it is unexported or something,
		// and we just continue onwards.
		if !fieldValue.CanSet() {
			continue
		}

		// If the name is empty string, then we're at the root, and we
		// don't dot-join the fields.
		if name != "" {
			fieldName = fmt.Sprintf("%s.%s", name, fieldName)
		}

		if err := d.decode(fieldName, rawMapVal.Interface(), fieldValue); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	if errs != nil {
		return errors2.New(errs)
	}

	return nil
}

func (d *Decoder) setInterface(_ string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	val.Set(dataVal)
	return nil
}

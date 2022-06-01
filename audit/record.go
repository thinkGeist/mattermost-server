// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package audit

// Meta represents metadata that can be added to a audit record as name/value pairs.
type Meta map[string]interface{}

// FuncMetaTypeConv defines a function that can convert meta data types into something
// that serializes well for audit records.
type FuncMetaTypeConv func(val interface{}) (newVal interface{}, converted bool)

// EventData -- The new audit log schema proposes that all audit log events include
// the EventData struct.
type EventData struct {
	Parameters       map[string]interface{} `json:"parameters"`         // Any parameters if relevant (and outside the actual payload)
	NewData          map[string]interface{} `json:"new_data"`           // the actual payload being processed. In most cases the JSON payload deserialized into interface{}
	PriorState       map[string]interface{} `json:"prior_state"`        // Prior state of the object being modified, nil if no prior state
	ResultingState   map[string]interface{} `json:"resulting_state"`    // Resulting object after creating or modifying it
	ResultObjectType string                 `json:"result_object_type"` // string representation of the object type. eg. "post"
}

// Auditable for sensitive object classes, consider implementing Auditable and include whatever the
// AuditableObject returns. For example: it's likely OK to write a user object to the
// audit logs, but not the user password in cleartext or hashed form
type Auditable interface {
	AuditableObject() map[string]interface{}
}

type AuditableMap map[string]interface{}

func (a AuditableMap) AuditableObject() map[string]interface{} {
	return a
}

type AuditableStringArray []string

// wrap a string array in a map so that the object to be audited is always a dictionary, never array
func (a AuditableStringArray) AuditableObject() map[string]interface{} {
	return map[string]interface{}{
		"array": a,
	}
}

type AuditableStringMap map[string]string

func (a AuditableStringMap) AuditableObject() map[string]interface{} {
	var r map[string]interface{}
	for key, val := range a {
		r[key] = val
	}
	return r
}

// Record provides a consistent set of fields used for all audit logging.
type Record struct {
	APIPath   string    `json:"api_path"`
	EventName string    `json:"event_name"`
	EventData EventData `json:"event_data"`
	Error     string    `json:"error"`
	Status    string    `json:"status"`
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Client    string    `json:"client"`
	IPAddress string    `json:"ip_address"`
	Meta      Meta      `json:"meta"`
	metaConv  []FuncMetaTypeConv
}

// Success marks the audit record status as successful.
func (rec *Record) Success() {
	rec.Status = Success
}

// Fail marks the audit record status as failed.
func (rec *Record) Fail() {
	rec.Status = Fail
}

// AddMeta adds a single name/value pair to this audit record's metadata.
// 6/1/22 With the new audit log schema being implemented, this method is
// patched to add the new_data object to the new event_data structure
func (rec *Record) AddMeta(name string, val Auditable) {
	rec.AddMetadata(val, nil, nil, name)
}

// AddMetadata Populates the `event_data` structure for the audit log entry. See above
// for description of the parameters
func (rec *Record) AddMetadata(newObject Auditable,
	priorObject Auditable,
	resultObject Auditable,
	resultObjectType string) {

	rec.EventData.ResultObjectType = resultObjectType

	if newObject != nil {
		rec.EventData.NewData = newObject.AuditableObject()
	}
	if priorObject != nil {
		rec.EventData.PriorState = priorObject.AuditableObject()
	}
	if resultObject != nil {
		rec.EventData.ResultingState = resultObject.AuditableObject()
	}
}

// AddMetaTypeConverter adds a function capable of converting meta field types
// into something more suitable for serialization.
func (rec *Record) AddMetaTypeConverter(f FuncMetaTypeConv) {
	rec.metaConv = append(rec.metaConv, f)
}

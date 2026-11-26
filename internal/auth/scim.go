package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"knotwork/internal/domain"

	filter "github.com/scim2/filter-parser/v2"
)

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimName struct {
	Formatted string `json:"formatted,omitempty"`
}

type scimUser struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       scimName    `json:"name,omitempty"`
	Emails     []scimEmail `json:"emails,omitempty"`
	Active     bool        `json:"active"`
}

type scimList struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	ItemsPerPage int        `json:"itemsPerPage,omitempty"`
	StartIndex   int        `json:"startIndex,omitempty"`
	Resources    []scimUser `json:"Resources"`
}

func (s *Service) RegisterSCIM(mux *http.ServeMux) {
	mux.Handle("GET /scim/v2/Users", s.RequireSCIM(http.HandlerFunc(s.scimListUsers)))
	mux.Handle("POST /scim/v2/Users", s.RequireSCIM(http.HandlerFunc(s.scimCreateUser)))
	mux.Handle("GET /scim/v2/Users/{id}", s.RequireSCIM(http.HandlerFunc(s.scimGetUser)))
	mux.Handle("PATCH /scim/v2/Users/{id}", s.RequireSCIM(http.HandlerFunc(s.scimPatchUser)))
	mux.Handle("DELETE /scim/v2/Users/{id}", s.RequireSCIM(http.HandlerFunc(s.scimDeleteUser)))
	// Groups are not stored; membership is managed by OIDC. Returning 501 is
	// explicit, unlike an empty 200 that an IdP may mistake for a successful sync.
	mux.Handle("GET /scim/v2/Groups", s.RequireSCIM(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSCIMError(w, http.StatusNotImplemented, "SCIM groups are not stored by Knotwork; membership is managed by OIDC")
	})))
	mux.Handle("POST /scim/v2/Groups", s.RequireSCIM(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSCIMError(w, http.StatusNotImplemented, "SCIM groups are not stored by Knotwork; membership is managed by OIDC")
	})))
}

func (s *Service) scimListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers(r.Context())
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not list users")
		return
	}

	rawFilter := strings.TrimSpace(r.URL.Query().Get("filter"))
	var expr filter.Expression
	if rawFilter != "" {
		expr, err = filter.ParseFilter([]byte(rawFilter))
		if err != nil {
			writeSCIMErrorType(w, http.StatusBadRequest, "invalidFilter", "invalid filter: "+err.Error())
			return
		}
		if err := validateSCIMFilter(expr); err != nil {
			writeSCIMErrorType(w, http.StatusBadRequest, "invalidFilter", err.Error())
			return
		}
	}

	resources := make([]scimUser, 0, len(users))
	for _, u := range users {
		if expr != nil {
			ok, err := matchSCIMFilter(u, expr)
			if err != nil {
				writeSCIMErrorType(w, http.StatusBadRequest, "invalidFilter", err.Error())
				return
			}
			if !ok {
				continue
			}
		}
		resources = append(resources, toSCIM(u))
	}

	if err := sortSCIM(resources, r.URL.Query().Get("sortBy"), r.URL.Query().Get("sortOrder")); err != nil {
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}

	startIndex, err := scimQueryInt(r, "startIndex", 1, 1)
	if err != nil {
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	count, err := scimQueryInt(r, "count", 100, 0)
	if err != nil {
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if count > 500 {
		count = 500
	}

	total := len(resources)
	page := []scimUser{}
	if startIndex <= total && count > 0 {
		start := startIndex - 1
		end := start + count
		if end > total {
			end = total
		}
		page = resources[start:end]
	}
	writeSCIM(w, http.StatusOK, scimList{
		Schemas:      []string{scimListSchema},
		TotalResults: total,
		ItemsPerPage: len(page),
		StartIndex:   startIndex,
		Resources:    page,
	})
}

func (s *Service) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required")
		return
	}
	externalID := in.ExternalID
	if externalID == "" {
		externalID = in.UserName
	}
	if existing, err := s.DB.GetUserBySCIMID(r.Context(), externalID); err == nil {
		writeSCIM(w, http.StatusConflict, toSCIM(existing))
		return
	}
	email := ""
	for _, e := range in.Emails {
		if e.Primary || email == "" {
			email = e.Value
		}
	}
	display := in.Name.Formatted
	if display == "" {
		display = in.UserName
	}
	user, err := s.DB.CreateSCIMUser(r.Context(), externalID, email, in.UserName, display)
	if err != nil {
		writeSCIMError(w, http.StatusConflict, "userName, email, or externalId already exists")
		return
	}
	writeSCIM(w, http.StatusCreated, toSCIM(user))
}

func (s *Service) scimGetUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.lookupSCIMUser(r)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, toSCIM(user))
}

type scimPatch struct {
	Schemas    []string             `json:"schemas"`
	Operations []scimPatchOperation `json:"Operations"`
}

type scimPatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type scimUserFields struct {
	scimID      string
	email       string
	username    string
	displayName string
	active      bool
}

func (s *Service) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.lookupSCIMUser(r)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	var patch scimPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(patch.Operations) == 0 {
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", "PATCH requires at least one operation")
		return
	}

	fields := scimUserFields{
		scimID:      user.SCIMID,
		email:       user.Email,
		username:    user.Username,
		displayName: user.DisplayName,
		active:      user.IsActive,
	}
	for _, op := range patch.Operations {
		if err := applySCIMOperation(&fields, op); err != nil {
			writeSCIMErrorType(w, http.StatusBadRequest, scimErrorType(err), err.Error())
			return
		}
	}
	if fields.username == "" {
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", "userName cannot be empty")
		return
	}
	if fields.email == "" {
		writeSCIMErrorType(w, http.StatusBadRequest, "invalidValue", "email cannot be empty")
		return
	}
	if err := s.DB.UpdateSCIMUser(r.Context(), user.ID, fields.scimID, fields.email, fields.username, fields.displayName, fields.active); err != nil {
		writeSCIMErrorType(w, http.StatusConflict, "uniqueness", "userName, email, or externalId already exists")
		return
	}
	updated, err := s.DB.GetUserByID(r.Context(), user.ID)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not load updated user")
		return
	}
	if !fields.active {
		s.Log.Warn("scim deactivated user", "user", updated.Username)
	}
	writeSCIM(w, http.StatusOK, toSCIM(updated))
}

func (s *Service) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.lookupSCIMUser(r)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err := s.DB.SetUserActive(r.Context(), user.ID, false); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "could not deactivate user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) lookupSCIMUser(r *http.Request) (domain.User, error) {
	id := r.PathValue("id")
	user, err := s.DB.GetUserByID(r.Context(), id)
	if err == nil {
		return user, nil
	}
	user, err = s.DB.GetUserBySCIMID(r.Context(), id)
	if err != nil {
		return domain.User{}, errors.New("user not found")
	}
	return user, nil
}

type scimValue struct {
	text    string
	boolean *bool
	present bool
}

func matchSCIMFilter(u domain.User, expr filter.Expression) (bool, error) {
	switch e := expr.(type) {
	case *filter.LogicalExpression:
		left, err := matchSCIMFilter(u, e.Left)
		if err != nil {
			return false, err
		}
		right, err := matchSCIMFilter(u, e.Right)
		if err != nil {
			return false, err
		}
		switch e.Operator {
		case filter.AND:
			return left && right, nil
		case filter.OR:
			return left || right, nil
		default:
			return false, fmt.Errorf("unsupported logical operator %q", e.Operator)
		}
	case *filter.NotExpression:
		value, err := matchSCIMFilter(u, e.Expression)
		if err != nil {
			return false, err
		}
		return !value, nil
	case *filter.AttributeExpression:
		return matchSCIMAttribute(u, *e)
	case *filter.ValuePath:
		return false, errors.New("value path filters are not supported")
	default:
		return false, fmt.Errorf("unsupported filter expression %T", expr)
	}
}

func matchSCIMAttribute(u domain.User, expr filter.AttributeExpression) (bool, error) {
	value, err := scimAttributeValue(u, expr.AttributePath)
	if err != nil {
		return false, err
	}
	return compareSCIM(value, expr.Operator, expr.CompareValue)
}

func validateSCIMFilter(expr filter.Expression) error {
	switch e := expr.(type) {
	case *filter.LogicalExpression:
		if err := validateSCIMFilter(e.Left); err != nil {
			return err
		}
		return validateSCIMFilter(e.Right)
	case *filter.NotExpression:
		return validateSCIMFilter(e.Expression)
	case *filter.AttributeExpression:
		return validateSCIMAttribute(e.Operator, e.AttributePath)
	case *filter.ValuePath:
		return errors.New("value path filters are not supported")
	default:
		return fmt.Errorf("unsupported filter expression %T", expr)
	}
}

func validateSCIMAttribute(op filter.CompareOperator, path filter.AttributePath) error {
	switch op {
	case filter.EQ, filter.NE, filter.CO, filter.SW, filter.EW, filter.PR:
	default:
		return fmt.Errorf("unsupported filter operator %q", op)
	}
	_, err := scimAttributeValue(domain.User{}, path)
	return err
}

func scimAttributeValue(u domain.User, path filter.AttributePath) (scimValue, error) {
	if uri := path.URI(); uri != "" && !strings.EqualFold(uri, scimUserSchema) {
		return scimValue{}, fmt.Errorf("unsupported attribute namespace %q", uri)
	}
	name := strings.ToLower(path.AttributeName)
	sub := strings.ToLower(path.SubAttributeName())
	switch name {
	case "id":
		return scimStringValue(u.ID), nil
	case "username":
		return scimStringValue(u.Username), nil
	case "externalid":
		return scimStringValue(u.SCIMID), nil
	case "displayname":
		return scimStringValue(u.DisplayName), nil
	case "active":
		active := u.IsActive
		return scimValue{boolean: &active, present: true}, nil
	case "name":
		if sub != "" && sub != "formatted" {
			return scimValue{}, fmt.Errorf("unsupported name sub-attribute %q", sub)
		}
		return scimStringValue(u.DisplayName), nil
	case "emails":
		if sub != "" && sub != "value" {
			return scimValue{}, fmt.Errorf("unsupported emails sub-attribute %q", sub)
		}
		return scimStringValue(u.Email), nil
	case "meta":
		switch sub {
		case "created":
			return scimStringValue(u.CreatedAt), nil
		case "lastmodified":
			return scimStringValue(u.UpdatedAt), nil
		default:
			return scimValue{}, fmt.Errorf("unsupported meta sub-attribute %q", sub)
		}
	default:
		return scimValue{}, fmt.Errorf("unsupported filter attribute %q", path.AttributeName)
	}
}

func scimStringValue(value string) scimValue {
	return scimValue{text: value, present: value != ""}
}

func compareSCIM(value scimValue, op filter.CompareOperator, want any) (bool, error) {
	if op == filter.PR {
		return value.present, nil
	}
	switch w := want.(type) {
	case bool:
		if value.boolean == nil {
			return false, errors.New("attribute is not boolean")
		}
		switch op {
		case filter.EQ:
			return *value.boolean == w, nil
		case filter.NE:
			return *value.boolean != w, nil
		default:
			return false, fmt.Errorf("operator %q is not supported for boolean attributes", op)
		}
	case string:
		if value.boolean != nil {
			b, err := strconv.ParseBool(w)
			if err != nil {
				return false, fmt.Errorf("value %q is not boolean", w)
			}
			switch op {
			case filter.EQ:
				return *value.boolean == b, nil
			case filter.NE:
				return *value.boolean != b, nil
			default:
				return false, fmt.Errorf("operator %q is not supported for boolean attributes", op)
			}
		}
		switch op {
		case filter.EQ:
			return strings.EqualFold(value.text, w), nil
		case filter.NE:
			return !strings.EqualFold(value.text, w), nil
		case filter.CO:
			return strings.Contains(strings.ToLower(value.text), strings.ToLower(w)), nil
		case filter.SW:
			return strings.HasPrefix(strings.ToLower(value.text), strings.ToLower(w)), nil
		case filter.EW:
			return strings.HasSuffix(strings.ToLower(value.text), strings.ToLower(w)), nil
		default:
			return false, fmt.Errorf("operator %q is not supported", op)
		}
	case nil:
		return !value.present, nil
	default:
		return false, fmt.Errorf("unsupported filter value type %T", want)
	}
}

type scimMutationError struct {
	kind    string
	message string
}

func (e *scimMutationError) Error() string { return e.message }

func scimErrorType(err error) string {
	var mutation *scimMutationError
	if errors.As(err, &mutation) {
		return mutation.kind
	}
	return "invalidValue"
}

func applySCIMOperation(fields *scimUserFields, op scimPatchOperation) error {
	opName := strings.ToLower(strings.TrimSpace(op.Op))
	if opName != "add" && opName != "replace" && opName != "remove" {
		return &scimMutationError{kind: "invalidSyntax", message: fmt.Sprintf("unsupported PATCH op %q", op.Op)}
	}
	path := strings.TrimSpace(op.Path)
	if path == "" {
		if opName == "remove" {
			return &scimMutationError{kind: "noTarget", message: "remove requires a path"}
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &object); err != nil {
			return &scimMutationError{kind: "invalidValue", message: "value must be an object when path is omitted"}
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := applySCIMOperation(fields, scimPatchOperation{Op: opName, Path: key, Value: object[key]}); err != nil {
				return err
			}
		}
		return nil
	}

	parsed, err := filter.ParsePath([]byte(path))
	if err != nil {
		return &scimMutationError{kind: "invalidPath", message: fmt.Sprintf("invalid PATCH path %q: %v", path, err)}
	}
	if parsed.ValueExpression != nil {
		return &scimMutationError{kind: "invalidPath", message: fmt.Sprintf("value path %q is not supported", path)}
	}
	if uri := parsed.AttributePath.URI(); uri != "" && !strings.EqualFold(uri, scimUserSchema) {
		return &scimMutationError{kind: "invalidPath", message: fmt.Sprintf("unsupported attribute namespace %q", uri)}
	}
	attr := strings.ToLower(parsed.AttributePath.AttributeName)
	sub := strings.ToLower(parsed.AttributePath.SubAttributeName())

	switch attr {
	case "active":
		if opName == "remove" {
			fields.active = false
			return nil
		}
		active, err := decodeSCIMBool(op.Value)
		if err != nil {
			return &scimMutationError{kind: "invalidValue", message: err.Error()}
		}
		fields.active = active
	case "username":
		if opName == "remove" {
			return &scimMutationError{kind: "invalidValue", message: "userName is required and cannot be removed"}
		}
		username, err := decodeSCIMString(op.Value)
		if err != nil || strings.TrimSpace(username) == "" {
			return &scimMutationError{kind: "invalidValue", message: "userName must be a non-empty string"}
		}
		fields.username = username
	case "externalid":
		if opName == "remove" {
			fields.scimID = ""
			return nil
		}
		externalID, err := decodeSCIMString(op.Value)
		if err != nil {
			return &scimMutationError{kind: "invalidValue", message: "externalId must be a string"}
		}
		fields.scimID = externalID
	case "name":
		if opName == "remove" {
			fields.displayName = ""
			return nil
		}
		switch sub {
		case "", "formatted":
			display, err := decodeSCIMName(op.Value)
			if err != nil {
				return &scimMutationError{kind: "invalidValue", message: err.Error()}
			}
			fields.displayName = display
		default:
			return &scimMutationError{kind: "invalidPath", message: fmt.Sprintf("unsupported PATCH path %q", path)}
		}
	case "displayname":
		if opName == "remove" {
			fields.displayName = ""
			return nil
		}
		display, err := decodeSCIMString(op.Value)
		if err != nil {
			return &scimMutationError{kind: "invalidValue", message: "displayName must be a string"}
		}
		fields.displayName = display
	case "emails":
		if opName == "remove" {
			return &scimMutationError{kind: "invalidValue", message: "email is required and cannot be removed"}
		}
		switch sub {
		case "":
			email, err := decodeSCIMEmail(op.Value)
			if err != nil {
				return &scimMutationError{kind: "invalidValue", message: err.Error()}
			}
			fields.email = email
		case "value":
			email, err := decodeSCIMString(op.Value)
			if err != nil || strings.TrimSpace(email) == "" {
				return &scimMutationError{kind: "invalidValue", message: "emails.value must be a non-empty string"}
			}
			fields.email = email
		default:
			return &scimMutationError{kind: "invalidPath", message: fmt.Sprintf("unsupported PATCH path %q", path)}
		}
	default:
		return &scimMutationError{kind: "invalidPath", message: fmt.Sprintf("unsupported PATCH path %q", path)}
	}
	return nil
}

func decodeSCIMBool(raw json.RawMessage) (bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		parsed, err := strconv.ParseBool(text)
		if err != nil {
			return false, errors.New("active must be a boolean")
		}
		return parsed, nil
	}
	var object struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &object); err == nil && len(object.Value) > 0 {
		return decodeSCIMBool(object.Value)
	}
	return false, errors.New("active must be a boolean")
}

func decodeSCIMString(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}
	var object struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &object); err == nil && object.Value != "" {
		return object.Value, nil
	}
	return "", errors.New("value must be a string")
}

func decodeSCIMName(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}
	var name scimName
	if err := json.Unmarshal(raw, &name); err == nil && name.Formatted != "" {
		return name.Formatted, nil
	}
	var object struct {
		Formatted string `json:"formatted"`
	}
	if err := json.Unmarshal(raw, &object); err == nil {
		return object.Formatted, nil
	}
	return "", errors.New("name.formatted must be a string")
}

func decodeSCIMEmail(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil && text != "" {
		return text, nil
	}
	var one scimEmail
	if err := json.Unmarshal(raw, &one); err == nil && one.Value != "" {
		return one.Value, nil
	}
	var many []scimEmail
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, email := range many {
			if email.Primary && email.Value != "" {
				return email.Value, nil
			}
		}
		for _, email := range many {
			if email.Value != "" {
				return email.Value, nil
			}
		}
	}
	return "", errors.New("emails must contain a value")
}

func sortSCIM(resources []scimUser, sortBy, sortOrder string) error {
	if sortBy == "" {
		return nil
	}
	key := strings.ToLower(sortBy)
	var less func(a, b scimUser) bool
	switch key {
	case "username":
		less = func(a, b scimUser) bool { return strings.ToLower(a.UserName) < strings.ToLower(b.UserName) }
	case "name.formatted":
		less = func(a, b scimUser) bool { return strings.ToLower(a.Name.Formatted) < strings.ToLower(b.Name.Formatted) }
	case "emails.value":
		less = func(a, b scimUser) bool {
			return strings.ToLower(scimPrimaryEmail(a)) < strings.ToLower(scimPrimaryEmail(b))
		}
	case "id":
		less = func(a, b scimUser) bool { return a.ID < b.ID }
	case "externalid":
		less = func(a, b scimUser) bool { return a.ExternalID < b.ExternalID }
	case "active":
		less = func(a, b scimUser) bool { return !a.Active && b.Active }
	default:
		return fmt.Errorf("unsupported sortBy %q", sortBy)
	}
	desc := strings.EqualFold(sortOrder, "descending") || strings.EqualFold(sortOrder, "desc")
	if sortOrder != "" && !desc && !strings.EqualFold(sortOrder, "ascending") && !strings.EqualFold(sortOrder, "asc") {
		return fmt.Errorf("invalid sortOrder %q", sortOrder)
	}
	sort.SliceStable(resources, func(i, j int) bool {
		if desc {
			return less(resources[j], resources[i])
		}
		return less(resources[i], resources[j])
	})
	return nil
}

func scimPrimaryEmail(u scimUser) string {
	for _, email := range u.Emails {
		if email.Primary {
			return email.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

func scimQueryInt(r *http.Request, name string, def, minimum int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return def, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum {
		return 0, fmt.Errorf("%s must be an integer >= %d", name, minimum)
	}
	return value, nil
}

func toSCIM(u domain.User) scimUser {
	out := scimUser{
		Schemas:    []string{scimUserSchema},
		ID:         u.ID,
		ExternalID: u.SCIMID,
		UserName:   u.Username,
		Name:       scimName{Formatted: u.DisplayName},
		Active:     u.IsActive,
	}
	if u.Email != "" {
		out.Emails = []scimEmail{{Value: u.Email, Primary: true, Type: "work"}}
	}
	return out
}

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	writeSCIMErrorType(w, status, "", detail)
}

func writeSCIMErrorType(w http.ResponseWriter, status int, scimType, detail string) {
	payload := map[string]any{
		"schemas": []string{scimErrorSchema},
		"detail":  detail,
		"status":  status,
	}
	if scimType != "" {
		payload["scimType"] = scimType
	}
	writeSCIM(w, status, payload)
}

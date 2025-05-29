// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldap

import (
	"fmt"
	"log"
	"strings"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/lor00x/goldap/message"

	ldap "github.com/casdoor/ldapserver"

	"github.com/xorm-io/builder"
)

type AttributeMapper func(user *object.User) message.AttributeValue

type GroupAttributeMapper func(group *object.Group) message.AttributeValue

type FieldRelation struct {
	userField     string
	notSearchable bool
	hideOnStarOp  bool
	fieldMapper   AttributeMapper
	groupFieldMapper GroupAttributeMapper
}

func (rel FieldRelation) GetField() (string, error) {
	if rel.notSearchable {
		return "", fmt.Errorf("attribute %s not supported", rel.userField)
	}
	return rel.userField, nil
}

func (rel FieldRelation) GetAttributeValue(user *object.User) message.AttributeValue {
	return rel.fieldMapper(user)
}

func (rel FieldRelation) GetGroupAttributeValue(group *object.Group) message.AttributeValue {
	return rel.groupFieldMapper(group)
}

var ldapAttributesMapping = map[string]FieldRelation{
	"cn": {userField: "name", hideOnStarOp: false, fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(user.Name)
	}, groupFieldMapper: func(group *object.Group) message.AttributeValue {
		return message.AttributeValue(group.Name)
	}},
	"uid": {userField: "id", hideOnStarOp: false, fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(user.Id)
	}, groupFieldMapper: func(group *object.Group) message.AttributeValue {
		return message.AttributeValue(group.GetId())
	}},
	"displayname": {userField: "displayName", fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(user.DisplayName)
	}, groupFieldMapper: func(group *object.Group) message.AttributeValue {
		return message.AttributeValue(group.DisplayName)
	}},
	"email": {userField: "email", fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(user.Email)
	}},
	"mail": {userField: "email", fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(user.Email)
	}},
	"mobile": {userField: "phone", fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(user.Phone)
	}},
	"title": {userField: "tag", fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(user.Tag)
	}},
	"objectclass": {userField: "tag", hideOnStarOp: true, fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue("posixAccount")
	}, groupFieldMapper: func(group *object.Group) message.AttributeValue {
		return message.AttributeValue("posixGroup")
	}},
	"gidnumber": {userField: "tag", fieldMapper: func(user *object.User) message.AttributeValue {
		return message.AttributeValue(fmt.Sprintf("%v", hash(user.Groups[0])))
	}, groupFieldMapper: func(group *object.Group) message.AttributeValue {
		return message.AttributeValue(fmt.Sprintf("%v", hash(group.GetId())))
	}},
	// "memberuid": {userField: "memberUid", groupFieldMapper: func(group *object.Group) message.AttributeValue {
	// 	users := object.GetGroupUsersWithoutError(group.GetId())
	// 	var memberUids []string
	// 	for _, user := range users {
	// 		memberUids = append(memberUids, user.Name)
	// 	}
	// 	return message.AttributeValue(strings.Join(memberUids, ","))
	// }},
	"userPassword": {
		userField:     "userPassword",
		hideOnStarOp: true,
		notSearchable: true,
		fieldMapper: func(user *object.User) message.AttributeValue {
			return message.AttributeValue(getUserPasswordWithType(user))
		},
	},
}

const ldapMemberOfAttr = "memberOf"


var AdditionalLdapAttributes []message.LDAPString

func init() {
	for k, v := range ldapAttributesMapping {
		if v.hideOnStarOp {
			continue
		}
		AdditionalLdapAttributes = append(AdditionalLdapAttributes, message.LDAPString(k))
	}
}

func getNameAndOrgFromDN(DN string) (string, string, error) {
	DNFields := strings.Split(DN, ",")
	params := make(map[string]string, len(DNFields))
	for _, field := range DNFields {
		if strings.Contains(field, "=") {
			k := strings.Split(field, "=")
			params[k[0]] = k[1]
		}
	}

	if params["cn"] == "" {
		params["cn"] = "*"
		//return "", "", fmt.Errorf("please use Admin Name format like cn=xxx,ou=xxx,dc=example,dc=com")
	}
	if params["ou"] == "" {
		return params["cn"], object.CasdoorOrganization, nil
	}
	return params["cn"], params["ou"], nil
}

func getNameAndOrgFromFilter(baseDN, filter string) (string, string, int) {
	if !strings.Contains(baseDN, "ou=") {
		return "", "", ldap.LDAPResultInvalidDNSyntax
	}

	name, org, err := getNameAndOrgFromDN(fmt.Sprintf("cn=%s,", getUsername(filter)) + baseDN)
	if err != nil {
		panic(err)
	}

	return name, org, ldap.LDAPResultSuccess
}

func getGroupSearchParamsFromFilter(baseDN, filter string) (string, string,string,string, int) {
	if!strings.Contains(baseDN, "ou=") {
		return "", "", "", "", ldap.LDAPResultInvalidDNSyntax
	}
	name, org, err := getNameAndOrgFromDN(fmt.Sprintf("cn=%s,", getUsername(filter)) + baseDN)
	if err!= nil {
		panic(err)
	}
	// Parse filter for memberUid and gidNumber
	memberUid := ""
	gidNumber := ""
	filter = strings.ToLower(filter)
	if strings.Contains(filter, "memberuid=") {
		start := strings.Index(filter, "memberuid=") + len("memberuid=")
		end := strings.Index(filter[start:], ")") + start
		memberUid = filter[start:end]
	}

	if strings.Contains(filter, "gidnumber=") {
		start := strings.Index(filter, "gidnumber=") + len("gidNumber=")
		end := strings.Index(filter[start:], ")") + start
		gidNumber = filter[start:end]
	}

	return name, org, memberUid, gidNumber, ldap.LDAPResultSuccess
}

func getUsername(filter string) string {
	nameIndex := strings.Index(filter, "cn=")
	if nameIndex == -1 {
		nameIndex = strings.Index(filter, "uid=")
		if nameIndex == -1 {
			return "*"
		} else {
			nameIndex += 4
		}
	} else {
		nameIndex += 3
	}

    // 使用rune来处理中文字符
    runes := []rune(filter)
    var nameRunes []rune
    for i := nameIndex; i < len(runes) && runes[i] != ')'; i++ {
        nameRunes = append(nameRunes, runes[i])
    }
    
    name := string(nameRunes)
    if name == "" {
        return "*"
    }
    return name
}

func stringInSlice(value string, list []string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func buildUserFilterCondition(filter interface{}) (builder.Cond, error) {
	switch f := filter.(type) {
	case message.FilterAnd:
		conditions := make([]builder.Cond, len(f))
		for i, v := range f {
			cond, err := buildUserFilterCondition(v)
			if err != nil {
				return nil, err
			}
			conditions[i] = cond
		}
		return builder.And(conditions...), nil
	case message.FilterOr:
		conditions := make([]builder.Cond, len(f))
		for i, v := range f {
			cond, err := buildUserFilterCondition(v)
			if err != nil {
				return nil, err
			}
			conditions[i] = cond
		}
		return builder.Or(conditions...), nil
	case message.FilterNot:
		cond, err := buildUserFilterCondition(f.Filter)
		if err != nil {
			return nil, err
		}
		return builder.Not{cond}, nil
	case message.FilterEqualityMatch:
		attr := string(f.AttributeDesc())

		if attr == ldapMemberOfAttr {
			var names []string
			groupId := string(f.AssertionValue())
			users := object.GetGroupUsersWithoutError(groupId)
			for _, user := range users {
				names = append(names, user.Name)
			}
			return builder.In("name", names), nil
		}

		if attr == "objectclass" {
			return builder.And(builder.Expr("1 = 1")), nil
		}

		field, err := getUserFieldFromAttribute(attr)
		if err != nil {
			return nil, err
		}
		return builder.Eq{field: string(f.AssertionValue())}, nil
	case message.FilterPresent:
		field, err := getUserFieldFromAttribute(string(f))
		if err != nil {
			return nil, err
		}
		return builder.NotNull{field}, nil
	case message.FilterGreaterOrEqual:
		field, err := getUserFieldFromAttribute(string(f.AttributeDesc()))
		if err != nil {
			return nil, err
		}
		return builder.Gte{field: string(f.AssertionValue())}, nil
	case message.FilterLessOrEqual:
		field, err := getUserFieldFromAttribute(string(f.AttributeDesc()))
		if err != nil {
			return nil, err
		}
		return builder.Lte{field: string(f.AssertionValue())}, nil
	case message.FilterSubstrings:
		field, err := getUserFieldFromAttribute(string(f.Type_()))
		if err != nil {
			return nil, err
		}
		var expr string
		for _, substring := range f.Substrings() {
			switch s := substring.(type) {
			case message.SubstringInitial:
				expr += string(s) + "%"
				continue
			case message.SubstringAny:
				expr += string(s) + "%"
				continue
			case message.SubstringFinal:
				expr += string(s)
				continue
			}
		}
		return builder.Expr(field+" LIKE ?", expr), nil
	default:
		return nil, fmt.Errorf("LDAP filter operation %#v not supported", f)
	}
}

func buildSafeCondition(filter interface{}) builder.Cond {
	condition, err := buildUserFilterCondition(filter)
	if err != nil {
		log.Printf("err = %v", err.Error())
		return builder.And(builder.Expr("1 != 1"))
	}
	return condition
}

func getSearchParamFromFilterString(filterString string, paramName string, defaultValue string) (value string) {
	filterString = strings.ToLower(filterString)
    paramName = strings.ToLower(paramName)
    
    start := strings.Index(filterString, paramName + "=")
    if start == -1 {
        return defaultValue
    }
    
    start += len(paramName) + 1 // 跳过参数名和等号
    end := strings.Index(filterString[start:], ")")
    if end == -1 || end == start{
        return defaultValue
    }
    
    value = filterString[start : start+end]
    return value
}

func GetFilteredUsers(m *ldap.Message) (filteredUsers []*object.User, code int) {
	var err error
	r := m.GetSearchRequest()

	name, org, code := getNameAndOrgFromFilter(string(r.BaseObject()), r.FilterString())
	if code != ldap.LDAPResultSuccess {
		name=getUsername(r.FilterString())
		org=m.Client.OrgName
	}

	if name == "*" { // get all users from organization 'org', or by gidNumber
		gidNumber := getSearchParamFromFilterString(r.FilterString(), "gidnumber", "")
		if gidNumber!= "" {
			allGroups, err := object.GetGroups(org)
			if err!= nil {
				panic(err)
			}
			for _, group := range allGroups {
				if fmt.Sprintf("%v", hash(group.GetId())) == gidNumber {
					groupUsers := object.GetGroupUsersWithoutError(group.GetId())					
					filteredUsers = append(filteredUsers, groupUsers...)
					break
				}
			}

			return filteredUsers, ldap.LDAPResultSuccess
		}
		
		if m.Client.IsGlobalAdmin && org == "*" {
			filteredUsers, err = object.GetGlobalUsersWithFilter(buildSafeCondition(r.Filter()))
			if err != nil {
				panic(err)
			}
			return filteredUsers, ldap.LDAPResultSuccess
		}
		if m.Client.IsGlobalAdmin || org == m.Client.OrgName {
			filteredUsers, err = object.GetUsersWithFilter(org, buildSafeCondition(r.Filter()))
			if err != nil {
				panic(err)
			}

			return filteredUsers, ldap.LDAPResultSuccess
		} else {
			return nil, ldap.LDAPResultInsufficientAccessRights
		}
	} else {
		requestUserId := util.GetId(m.Client.OrgName, m.Client.UserName)
		userId := util.GetId(org, name)

		hasPermission, err := object.CheckUserPermission(requestUserId, userId, true, "en")
		if !hasPermission {
			log.Printf("err = %v", err.Error())
			return nil, ldap.LDAPResultInsufficientAccessRights
		}

		user, err := object.GetUser(userId)
		if err != nil {
			panic(err)
		}

		if user != nil {
			filteredUsers = append(filteredUsers, user)
			return filteredUsers, ldap.LDAPResultSuccess
		}

		organization, err := object.GetOrganization(util.GetId("admin", org))
		if err != nil {
			panic(err)
		}

		if organization == nil {
			return nil, ldap.LDAPResultNoSuchObject
		}

		if !stringInSlice(name, organization.Tags) {
			return nil, ldap.LDAPResultNoSuchObject
		}

		users, err := object.GetUsersByTagWithFilter(org, name, buildSafeCondition(r.Filter()))
		if err != nil {
			panic(err)
		}

		filteredUsers = append(filteredUsers, users...)
		return filteredUsers, ldap.LDAPResultSuccess
	}
}

func GetFilteredGroups(m *ldap.Message) (filteredGroups []*object.Group, code int) {
	var err error
	r := m.GetSearchRequest()
	groupName, org, memberUid, gidNumber, code := getGroupSearchParamsFromFilter(string(r.BaseObject()), r.FilterString())
	if code!= ldap.LDAPResultSuccess {
		groupName = getUsername(r.FilterString())
		org = m.Client.OrgName
	}
	if groupName != "*" { //exactly match
		groupId := util.GetId(org, groupName)
		group, err := object.GetGroup(groupId)
		if err!= nil {
			panic(err)
		}
		if group!= nil {
			filteredGroups = append(filteredGroups, group)
		}

		return filteredGroups, ldap.LDAPResultSuccess
	}

	allGroups,err:= object.GetGroups(org);
	if err!= nil {
		panic(err)
	}

	if(gidNumber != ""){
		for i, group := range allGroups {
			if fmt.Sprintf("%v", hash(group.GetId())) == gidNumber {
				filteredGroups = append(filteredGroups, group)
				allGroups = append(allGroups[:i], allGroups[i+1:]...)
				break;
			}
		}
	}

	if(memberUid!= ""){ //now only support OR serach
		for _, group := range allGroups {
			users := object.GetGroupUsersWithoutError(group.GetId())
			for _, user := range users {
				if user.Name == memberUid {
					filteredGroups = append(filteredGroups, group)
				}
			}
		}
	}


	if groupName == "*" && memberUid == "" && gidNumber == "" { // get all groups from organization 'org'
		if m.Client.IsGlobalAdmin && org == "*" {
			filteredGroups, err := object.GetGroups("*")
			if err!= nil {
				panic(err)
			}
			
			return filteredGroups, ldap.LDAPResultSuccess
		}
		if m.Client.IsGlobalAdmin || org == m.Client.OrgName {
			filteredGroups, err = object.GetGroups(org)
		}
		if err!= nil {
			panic(err)
		}
	}
	return filteredGroups, ldap.LDAPResultSuccess
}

// get user password with hash type prefix
// TODO not handle salt yet
// @return {md5}5f4dcc3b5aa765d61d8327deb882cf99
func getUserPasswordWithType(user *object.User) string {
	org, err := object.GetOrganizationByUser(user)
	if err != nil {
		panic(err)
	}

	if org.PasswordType == "" || org.PasswordType == "plain" {
		return user.Password
	}
	prefix := org.PasswordType
	if prefix == "salt" {
		prefix = "sha256"
	} else if prefix == "md5-salt" {
		prefix = "md5"
	} else if prefix == "pbkdf2-salt" {
		prefix = "pbkdf2"
	}
	return fmt.Sprintf("{%s}%s", prefix, user.Password)
}

func getAttribute(attributeName string, user *object.User) message.AttributeValue {
	v, ok := ldapAttributesMapping[strings.ToLower(attributeName)]
	if !ok {
		return ""
	}
	return v.GetAttributeValue(user)
}

func getGroupAttribute(attributeName string, group *object.Group) message.AttributeValue {
	v, ok := ldapAttributesMapping[strings.ToLower(attributeName)]
	if!ok {
		return ""
	}
	return v.GetGroupAttributeValue(group)
}

func getUserFieldFromAttribute(attributeName string) (string, error) {
	v, ok := ldapAttributesMapping[strings.ToLower(attributeName)]
	if !ok {
		return "", fmt.Errorf("attribute %s not supported", attributeName)
	}
	return v.GetField()
}

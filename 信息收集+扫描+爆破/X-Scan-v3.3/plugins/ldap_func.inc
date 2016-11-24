# -*- Fundamental -*-
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# ldap_func.inc
# $Revision: 1.6 $
#



global_var _ldap_socket, _ldap_error, _msgid;


# LDAP request/response codes

LDAP_BIND_REQUEST      = 0x60;
LDAP_BIND_RESPONSE     = 0x61;
LDAP_SEARCH_REQUEST    = 0x63;
LDAP_SEARCH_RES_ENTRY  = 0x64;
LDAP_SEARCH_RES_DONE   = 0x65;
LDAP_MODIFY_REQUEST    = 0x66;
LDAP_MODIFY_RESPONSE   = 0x67;
LDAP_EXTENDED_REQUEST  = 0x77;
LDAP_EXTENDED_RESPONSE = 0x78;

# BER tags

LDAP_BOOLEAN_TAG         = 0x01;
LDAP_INTEGER_TAG         = 0x02;
LDAP_ENUMERATED_TAG      = 0x0a;
LDAP_SEQUENCE_TAG        = 0x30;
LDAP_STRING_SEQUENCE_TAG = 0x31;
LDAP_AUTHENTICATION_TAG  = 0x80;
LDAP_FILTER_TAG          = 0x87;

# LDAP internal error codes

LDAP_ERROR_SOCK_NO_DATA        = 1001;
LDAP_ERROR_SOCK_INVALID_TAG    = 1002;
LDAP_ERROR_INVALID_ID          = 1003;
LDAP_ERROR_DECODE              = 1004;

# codes

MODIFY_DELETE   = 2;



#---------------------------------------------------------#
# Function    : mklist                                    #
# Description : Transforms arguments into a list. Replaces#
#               make_list to not destroy a list given as  #
#               argument.                                 #
#---------------------------------------------------------#

function mklist()
{
 local_var ret;
 local_var i, l;

 l = max_index (_FCT_ANON_ARGS);

 if (NASL_LEVEL >= 3000)
   ret  = fill_list(length:l, value:0);
 else
   ret = NULL;

 for (i=0 ; i<l ; i++)
   ret[i] = _FCT_ANON_ARGS[i];

 return ret;
}


#---------------------------------------------------------#
# Function    : ldap_init                                 #
# Description : Inits internal ldap data.                 #
#---------------------------------------------------------#

function ldap_init(socket)
{
 _msgid = 1;
 _ldap_socket = socket; 
}


#---------------------------------------------------------#
# Function    : ldap_get_last_error                       #
# Description : Gets last ldap-related error.             #
#---------------------------------------------------------#

function ldap_get_last_error()
{
 if (isnull(_ldap_error)) return NULL;
 else return _ldap_error;
}


#---------------------------------------------------------#
# Function    : ldap_set_error                            #
# Description : Sets ldap error and return NULL.          #
#---------------------------------------------------------#

function ldap_set_error()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];

 _ldap_error = l;
 return NULL;
}


#---------------------------------------------------------#
# Function    : der_encode_enumerated                     #
# Description : Encodes an enumerated value.              #
#---------------------------------------------------------#

function der_encode_enumerated(e)
{
 local_var val,j,tmp;

 if (isnull (e))
   return NULL;

 val[0] = e & 255;
 val[1] = (e>>8)  & 255;
# val[2] = (e>>16) & 255;
# val[3] = (e>>24) & 255;

 j = 3;
 while ((val[j] == 0) && (j != 0))
   j--;

 tmp = NULL;
 while (j != 0)
 {
  tmp += raw_string (val[j]);
  j--;
 }

 tmp += raw_string (val[j]);
 

 return der_encode(tag:LDAP_ENUMERATED_TAG, data:tmp);
}


#---------------------------------------------------------#
# Function    : der_encode_boolean                        #
# Description : Encodes a boolean.                        #
#---------------------------------------------------------#

function der_encode_boolean(b)
{
 return der_encode(tag:LDAP_BOOLEAN_TAG, data:raw_string(b));
}


#---------------------------------------------------------#
# Function    : der_encode_filter                         #
# Description : Encodes a filter.                         #
#---------------------------------------------------------#

function der_encode_filter(filter)
{
 return der_encode(tag:LDAP_FILTER_TAG, data:filter);
}


#---------------------------------------------------------#
# Function    : ldap_request_sendrecv                     #
# Description : Sends ldap request and parse the response #
#---------------------------------------------------------#

function ldap_request_sendrecv(data)
{
 local_var buf, len, length_buf, msgid, id;

 send(socket:_ldap_socket, data:data);

 buf = recv(socket:_ldap_socket, length:2, min:2);
 if (strlen(buf) < 2)
   return ldap_set_error(LDAP_ERROR_SOCK_NO_DATA);

 if (ord(buf[0]) != LDAP_SEQUENCE_TAG)
   return ldap_set_error(LDAP_ERROR_SOCK_INVALID_TAG);

 len = ord(buf[1]);

 if (len > 127)
 {
  len -= 128;
  length_buf = recv(socket:_ldap_socket, length:len, min:len);
  if (strlen(length_buf) < len)
    return ldap_set_error(LDAP_ERROR_SOCK_NO_DATA);

  len = integer (i:length_buf);
 }
 
 buf = recv(socket:_ldap_socket, length:len, min:len);
 if (strlen(buf) < len)
   return ldap_set_error(LDAP_ERROR_SOCK_NO_DATA);

 msgid = der_decode(data:buf, pos:0);
 if (isnull(msgid) || msgid[0] != LDAP_INTEGER_TAG)
   return ldap_set_error(LDAP_ERROR_DECODE);

 id = integer(i:msgid[1]);
 if (id != _msgid)
   return ldap_set_error(LDAP_ERROR_INVALID_ID);

 _msgid++;

 data = der_decode(data:buf, pos:msgid[2]);
 if (isnull(data))
   return ldap_set_error(LDAP_ERROR_DECODE);

 return data;
}


#---------------------------------------------------------#
# Function    : ldap_request                              #
# Description : Creates ldap request.                     #
#---------------------------------------------------------#

function ldap_request(code, data)
{
 local_var l;

 l = der_encode_int(i:_msgid) + der_encode(tag:code, data:data);

 return der_encode_list(list:l);
}


#---------------------------------------------------------#
# Function    : ldap_bind_request                         #
# Description : Creates ldap bind request.                #
#---------------------------------------------------------#

function ldap_bind_request()
{
 local_var data, ret;

 data = 
	der_encode_int(i:3)                 +  # LDAP version
	der_encode_octet_string(string:"")  +  # name
	der_encode(tag:LDAP_AUTHENTICATION_TAG, data:"");

 return ldap_request(code:LDAP_BIND_REQUEST, data:data);
}


#---------------------------------------------------------#
# Function    : ldap_parse_enumerated                     #
# Description : Parses encoded result field.              #
#---------------------------------------------------------#

function ldap_parse_enumerated(data)
{
 local_var tmp;

 tmp = der_parse_data(tag:LDAP_ENUMERATED_TAG, data:data);
 if (isnull(tmp))
   return ldap_set_error(LDAP_ERROR_DECODE);

 return integer(i:tmp);
}


#---------------------------------------------------------#
# Function    : ldap_parse_response                       #
# Description : Parses encoded response.                  #
#---------------------------------------------------------#

function ldap_parse_response(data)
{
 local_var list, result, dn, msg;

 list = der_parse_list(list:data);
 if (isnull(list) || list[0] < 3)
   return ldap_set_error(LDAP_ERROR_DECODE);

 result = ldap_parse_enumerated(data:list[1]);
 if (isnull(result))
   return ldap_set_error(LDAP_ERROR_DECODE);

 dn = der_parse_octet_string(string:list[2]);
 if (isnull(result))
   return ldap_set_error(LDAP_ERROR_DECODE);

 msg = der_parse_octet_string(string:list[3]);
 if (isnull(result))
   return ldap_set_error(LDAP_ERROR_DECODE);

 return mklist(result, dn, msg);
}


#---------------------------------------------------------#
# Function    : ldap_parse_bind_response                  #
# Description : Parses encoded bind response.             #
#---------------------------------------------------------#

function ldap_parse_bind_response(data)
{
 return ldap_parse_response(data:data);
}


#---------------------------------------------------------#
# Function    : ldap_parse_modify_response                #
# Description : Parses encoded modify response.           #
#---------------------------------------------------------#

function ldap_parse_modify_response(data)
{
 return ldap_parse_response(data:data);
}


#---------------------------------------------------------#
# Function    : ldap_modify_request                       #
# Description : Creates ldap modify request.              #
#---------------------------------------------------------#

function ldap_modify_request(object, operation, data)
{
 local_var item, mlist, req, list;

 item = 
	der_encode_int(i:operation) +
	der_encode_list(list:data);

 mlist = der_encode_list(list:item); # ItemList

 req = 
	der_encode_octet_string (string:object) +
	der_encode_list(list:mlist);


 return ldap_request(code:LDAP_MODIFY_REQUEST, data:req);
}


#---------------------------------------------------------#
# Function    : ldap_search_request                       #
# Description : Creates ldap search request.              #
#---------------------------------------------------------#

function ldap_search_request(object, filter, attributes)
{
 local_var req;

 req = 
	der_encode_octet_string (string:object) +
        der_encode_enumerated(e:0) +
        der_encode_enumerated(e:0) +
        der_encode_int(i:0) +
        der_encode_int(i:0) +
        der_encode_boolean(b:FALSE) +
	der_encode_filter(filter:filter) +
	der_encode_list(list:attributes);


 return ldap_request(code:LDAP_SEARCH_REQUEST, data:req);
}


#---------------------------------------------------------#
# Function    : ldap_parse_search_entry                   #
# Description : Parses encoded search entry.              #
#---------------------------------------------------------#

function ldap_parse_search_entry(data)
{
 local_var list, object, ret, i, tlist, type, values, vlist, j;

 list = der_parse_list(list:data);
 if (isnull(list) || list[0] < 2)
   return ldap_set_error(LDAP_ERROR_DECODE);

 object = der_parse_octet_string(string:list[1]);

 list = der_parse_data(tag:LDAP_SEQUENCE_TAG, data:list[2]);
 if (isnull(list))
   return ldap_set_error(LDAP_ERROR_DECODE);

 list = der_parse_list(list:list);
 if (isnull(list))
   return ldap_set_error(LDAP_ERROR_DECODE);

 ret = NULL;
 for (i=1; i<=list[0]; i++)
 {
  tlist = der_parse_data(tag:LDAP_SEQUENCE_TAG, data:list[i]);
  if (isnull(tlist))
    return ldap_set_error(LDAP_ERROR_DECODE);

  tlist = der_parse_list(list:tlist);
  if (isnull(tlist) || tlist[0] != 2)
    return ldap_set_error(LDAP_ERROR_DECODE);

  type = der_parse_octet_string(string:tlist[1]);
  values = der_parse_data(tag:LDAP_STRING_SEQUENCE_TAG, data:tlist[2]);
  if (isnull(tlist))
    return ldap_set_error(LDAP_ERROR_DECODE);

  values = der_parse_list(list:values);
  if (isnull(values))
    return ldap_set_error(LDAP_ERROR_DECODE);

  vlist = NULL;
  for (j=1; j<=values[0]; j++) 
    vlist[j-1] = der_parse_octet_string(string:values[j]);

  ret[i-1] = mklist(type, vlist);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : ldap_extended_request                     #
# Description : Creates an ldap extended request.         #
#---------------------------------------------------------#

function ldap_extended_request(oid, val)
{
  local_var req;

  # nb: the args are octet strings that that must use a 
  #     context-specific rather than universal class.
  req = der_encode(tag:(0x04|0x80), data:oid);
  if (!isnull(val)) req += der_encode(tag:(0x04|0x80), data:val);

  return ldap_request(code:LDAP_EXTENDED_REQUEST, data:req);
}


#---------------------------------------------------------#
# Function    : ldap_parse_extended_response              #
# Description : Parses encoded extended response.         #
#---------------------------------------------------------#

function ldap_parse_extended_response(data)
{
  local_var list, result, dn, msg, oid, val;

  list = der_parse_list(list:data);
  if (isnull(list) || list[0] < 3)
    return ldap_set_error(LDAP_ERROR_DECODE);

  result = ldap_parse_enumerated(data:list[1]);
  if (isnull(result))
    return ldap_set_error(LDAP_ERROR_DECODE);

  if (substr_at_offset(str:list[2], blob:'\x04\x00', offset:0)) dn = "";
  else
  {
    dn = der_parse_octet_string(string:list[2]);
    if (isnull(dn))
      return ldap_set_error(LDAP_ERROR_DECODE);
  }

  if (substr_at_offset(str:list[3], blob:'\x04\x00', offset:0)) msg = "";
  else
  {
    msg = der_parse_octet_string(string:list[3]);
    if (isnull(msg))
      return ldap_set_error(LDAP_ERROR_DECODE);
  }

  if (list[0] > 3)
  {
    if (substr_at_offset(str:list[4], blob:'\x04\x00', offset:0)) oid = "";
    else
    {
      oid = der_parse_octet_string(string:list[4]);
      if (isnull(oid))
        return ldap_set_error(LDAP_ERROR_DECODE);
    }
  }
  else oid = "";

  if (list[0] > 4)
  {
    if (substr_at_offset(str:list[5], blob:'\x04\x00', offset:0)) val = "";
    else
    {
      val = der_parse_octet_string(string:list[5]);
      if (isnull(val))
        return ldap_set_error(LDAP_ERROR_DECODE);
    }
  }
  else val = "";

  return mklist(result, dn, msg, oid, val);
}


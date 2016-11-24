# -*- Fundamental -*-
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/HomeFeed.pdf
#  http://www.nessus.org/plugins/ProfessionalFeed.pdf
#
#
# @NOGPL@
#
# x509_func.inc
# $Revision: 1.6 $
#


include("misc_func.inc");
include("ssl_funcs.inc");
include("kerberos_func.inc");
include("byte_func.inc");



# OCSP
oid_name["1.3.6.1.5.5.7.48.1"] = "Online Certificate Status Protocol";
oid_name["1.3.6.1.5.5.7.48.2"] = "Certificate Authority Issuers";

# certificate RFC 2459
oid_name["1.3.6.1.5.5.7.3.1"] = "Web Server Authentication";
oid_name["1.3.6.1.5.5.7.3.2"] = "Web Client Authentication";
oid_name["1.3.6.1.5.5.7.3.3"] = "Code Signing";
oid_name["1.3.6.1.5.5.7.3.4"] = "E-Mail Protection";
oid_name["1.3.6.1.5.5.7.3.5"] = "IPSEC End System";
oid_name["1.3.6.1.5.5.7.3.6"] = "IPSEC Tunnel";
oid_name["1.3.6.1.5.5.7.3.7"] = "IPSEC User";
oid_name["1.3.6.1.5.5.7.3.8"] = "Time Stamping";
oid_name["1.3.6.1.5.5.7.3.9"] = "OCSP Responder";

# Netscape Policy
oid_name["2.16.840.1.113730.4.1"] = "Strong Crypto Export Approved";

# PKIX
oid_name["1.3.6.1.5.5.7.1.1"]     = "Authority Information Access";

# crypto
oid_name["1.2.840.113549.1.1.1"]  = "RSA Encryption";
oid_name["1.2.840.113549.1.1.2"]  = "MD2 With RSA Encryption";
oid_name["1.2.840.113549.1.1.3"]  = "MD4 With RSA Encryption";
oid_name["1.2.840.113549.1.1.4"]  = "MD5 With RSA Encryption";
oid_name["1.2.840.113549.1.1.5"]  = "SHA-1 With RSA Encryption";

# PKCS#9
oid_name["1.2.840.113549.1.9.1"]  = "Email Address";
oid_name["1.2.840.113549.1.9.2"]  = "Unstructured Name";
oid_name["1.2.840.113549.1.9.3"]  = "Content Type";
oid_name["1.2.840.113549.1.9.4"]  = "Message Digest";
oid_name["1.2.840.113549.1.9.5"]  = "Signing Time";
oid_name["1.2.840.113549.1.9.6"]  = "Counter Signature";
oid_name["1.2.840.113549.1.9.7"]  = "Challenge Password";
oid_name["1.2.840.113549.1.9.8"]  = "Unstructured Address";
oid_name["1.2.840.113549.1.9.9"]  = "Extended Certificate Attributes";
oid_name["1.2.840.113549.1.9.15"] = "S/MIME Capabilities";
oid_name["1.2.840.113549.1.9.20"] = "Friendly Name";
oid_name["1.2.840.113549.1.9.21"] = "Local Key ID";


# DC
oid_name["0.9.2342.19200300.100.1.1"] = "User Id";
oid_name["0.9.2342.19200300.100.1.3"] = "Email Address";
oid_name["0.9.2342.19200300.100.1.25"] = "Domain Component";

# Name data
oid_name["2.5.4.3"]   = "Common Name";
oid_name["2.5.4.4"]   = "Surname";
oid_name["2.5.4.6"]   = "Country";
oid_name["2.5.4.7"]   = "Locality";
oid_name["2.5.4.8"]   = "State/Province";
oid_name["2.5.4.10"]  = "Organization";
oid_name["2.5.4.11"]  = "Organization Unit";
oid_name["2.5.4.12"]  = "Title";
oid_name["2.5.4.17"]  = "Postal Code";
oid_name["2.5.4.41"]  = "Name";
oid_name["2.5.4.42"]  = "Given Name";
oid_name["2.5.4.43"]  = "Initials";

# Certificate data
oid_name["2.5.29.5"]  = "Subject Directory Attributes";
oid_name["2.5.29.9"]  = "Subject Directory Attributes";
oid_name["2.5.29.14"] = "Subject Key Identifier";
oid_name["2.5.29.15"] = "Key Usage";
oid_name["2.5.29.16"] = "Key Usage Period";
oid_name["2.5.29.17"] = "Subject Alternative Name";
oid_name["2.5.29.18"] = "Issuer Alternative Name";
oid_name["2.5.29.19"] = "Basic Constraints";
oid_name["2.5.29.20"] = "CRL Number";
oid_name["2.5.29.21"] = "CRL Reason Code";
oid_name["2.5.29.23"] = "Hold Instruction Code";
oid_name["2.5.29.24"] = "Invalid Date";
oid_name["2.5.29.27"] = "Delta CRL Indicator";
oid_name["2.5.29.28"] = "Issuing Distribution Point";
oid_name["2.5.29.29"] = "Issuer";
oid_name["2.5.29.30"] = "Name Constraints";
oid_name["2.5.29.31"] = "CRL Distribution Points";
oid_name["2.5.29.32"] = "Policies";
oid_name["2.5.29.33"] = "Policy Mappings";
oid_name["2.5.29.34"] = "Policy Constraints";
oid_name["2.5.29.35"] = "Authority Key Identifier";
oid_name["2.5.29.36"] = "Policy Constraints";
oid_name["2.5.29.37"] = "Extended Key Usage";


# Netscape cert extensions
oid_name["2.16.840.1.113730.1.13"] = "Comment";

# PKIX Extended Key Usage Extension Uses
oid_name["1.3.6.1.4.1.311.10.3.1"] = "Certificate trust list signing";
oid_name["1.3.6.1.4.1.311.10.3.3"] = "Microsoft Server Gated Crypto (SGC)";
oid_name["1.3.6.1.4.1.311.10.3.4"] = "Microsoft Encrypted File System";
oid_name["2.16.840.1.113730.4.1"] = "Netscape SGC";

# PKIX
oid_name["1.3.6.1.5.5.7.2.1"] = "Certification Practice Statement";
oid_name["1.3.6.1.5.5.7.2.2"] = "User Notice";

OID_CPS_POINTER = "1.3.6.1.5.5.7.2.1";
OID_USER_NOTICE = "1.3.6.1.5.5.7.2.2";


global_var known_extensions;

EXTN_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
EXTN_KEY_USAGE = "2.5.29.15";
EXTN_EXTENDED_KEY_USAGE = "2.5.29.37";
EXTN_CRL_DIST_POINTS = "2.5.29.31";
EXTN_AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1";
EXTN_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
EXTN_SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";
EXTN_CERTIFICATE_COMMENT = "2.16.840.1.113730.1.13";
EXTN_CERTIFICATE_POLICIES = "2.5.29.32";


known_extensions[EXTN_KEY_USAGE] = TRUE;  # Key Usage
known_extensions[EXTN_EXTENDED_KEY_USAGE] = TRUE;  # Extended Key Usage
known_extensions[EXTN_CRL_DIST_POINTS] = TRUE; # CRL Distribution Points
known_extensions[EXTN_AUTHORITY_INFORMATION_ACCESS] = TRUE; # Authority Information Access
known_extensions[EXTN_AUTHORITY_KEY_IDENTIFIER] = TRUE; # Authority Key Identifier
known_extensions[EXTN_SUBJECT_KEY_IDENTIFIER] = TRUE; # Subject Key Identifier
known_extensions[EXTN_SUBJECT_ALTERNATIVE_NAME] = TRUE; # Subject Alternative Name
known_extensions[EXTN_CERTIFICATE_COMMENT] = TRUE; # Netscape Certificate Comment
known_extensions[EXTN_CERTIFICATE_POLICIES] = TRUE; # Policies


function inv8 (x)
{
 local_var val, i;

 val = 0;

 for (i=0; i<8; i++)
   val = val + (((x >> (7-i)) & 1) << i);

 return val;
}


function parse_publickey_info(pki)
{
 local_var pos, ret, ai, tmp, seq, pk, e, n;

 pos = 0;

 ret = der_decode(data:pki, pos:pos);
 if (isnull(ret) || ret[0] != 0x30) return NULL;
 pos = ret[2];

 ret = der_parse_list(list:ret[1]);
 if (isnull(ret) || ret[0] != 2) return NULL;
 ai = der_parse_oid(oid:ret[1]);

 ret = der_decode(data:pki, pos:pos);
 if (isnull(ret) || ret[0] != 0x03) return NULL;

 # RSA only
 if (ai >!< "1.2.840.113549.1.1.1") 
 {
  display("PKI: unsupported key type!\n");
  return NULL;
 }

 seq = der_parse_sequence (seq:substr(ret[1], 1, strlen(ret[1])-1),list:TRUE);
 if (isnull(seq) || seq[0] != 2)
   return NULL;

 n = der_parse_data(tag:0x02, data:seq[1]);
 e = der_parse_data(tag:0x02, data:seq[2]);

 tmp = NULL;
 tmp[0] = ai;
 tmp[1] = make_list(n,e);

 return tmp;
}


function parse_attribute_type_and_value(a)
{
 local_var seq, list, oid, ret, at;

 seq = der_parse_data(tag:0x31, data:a);
 if (isnull(seq)) return NULL;

 list = der_parse_sequence(seq:seq, list:TRUE);
 if (isnull(list) || list[0] != 2) return NULL;

 oid = der_parse_oid(oid:list[1]);
 if (isnull(oid)) return NULL;

 ret = der_decode(data:list[2]);
 if (isnull(ret)) return NULL;

 # uTF8String && PrintableString && T61String && IA5String
 if (ret[0] != 12 && ret[0] != 19 && ret[0] != 20 && ret[0] != 22)
 {
  display("AT: unsupported string encoding: ", ret[0], " !\n");
  return NULL;
 }

 at = NULL;
 at[0] = oid;
 at[1] = ret[1];

 return at;
}


function parse_rdn_sequence(seq)
{
 local_var list, rdns, num, i, ret;

 list = der_parse_list(list:seq);
 if (isnull(list)) return NULL;

 rdns = NULL;

 num = list[0];
 for (i=0; i<num; i++)
 {
  ret = parse_attribute_type_and_value(a:list[i+1]);
  if (isnull(ret)) return NULL;

  rdns[i] = ret;
 }

 return rdns;
}


global_var mons;

mons[1]  = "Jan";
mons[2]  = "Feb";
mons[3]  = "Mar";
mons[4]  = "Apr";
mons[5]  = "May";
mons[6]  = "Jun";
mons[7]  = "Jul";
mons[8]  = "Aug";
mons[9]  = "Sep";
mons[10] = "Oct";
mons[11] = "Nov";
mons[12] = "Dec";


function int2()
{
 local_var i, temp;
 i = _FCT_ANON_ARGS[0];

 temp = int(i);
 if (i < 10)
   temp = "0" + temp;

 return temp;
}


function convert_all_time(year, time)
{
 local_var i, temp;

 temp = NULL;

 for (i=0; i<6; i++)
   temp[i] = int(substr(time, i*2, (i+1)*2-1));

 return string(
      mons[temp[0]], " ",
      int2(temp[1]), " ",
      int2(temp[2]), ":", int2(temp[3]), ":", int2(temp[4]), " ",
      year, " GMT"
    );
}


# rfc3280: UTCTime -> YYMMDDHHMMSSZ GMT
function convert_utc_time(time)
{
 local_var year;

 if (strlen(time) != 13) return time;

 year = int(substr(time, 0, 1));
 if (year >= 50)
   year = 1900+year;
 else
   year = 2000+year;

 return convert_all_time(year:year, time:substr(time, 2, 11));
}


# rfc3280: GeneralizedTime -> YYMMDDHHMMSSZ GMT
function convert_generalized_time(time)
{
 local_var year;

 if (strlen(time) != 15) return time;

 year = int(substr(time, 0, 2));

 return convert_all_time(year:year, time:substr(time, 4, 13));
}


function parse_time(time)
{
 local_var ret;

 ret = der_decode(data:time);
 if (isnull(ret) || (ret[0] != 0x17 && ret[0] != 0x18)) return NULL;

 # UTCTime
 if (ret[0] == 0x17)
   return convert_utc_time(time:ret[1]);

 # GeneralizedTime
 if (ret[0] == 0x18)
   return convert_generalized_time(time:ret[1]);

 return NULL;
}


function parse_algorithm_identifier(ai)
{
 local_var ret;

 ret = der_parse_sequence(seq:ai, list:TRUE);
 if (isnull(ret) || ret[0] != 2) return NULL;

 return der_parse_oid(oid:ret[1]);
}


function parse_flags(data)
{
 local_var bits, val, i, len;

 bits = der_parse_data(tag:0x03, data:data);
 if (isnull(bits)) return NULL;

 val = 0;
 len = strlen(bits);
 
 for (i=0; i<len; i++)
   val = (val << 8) + inv8(x:ord(bits[i]));

 return val;
}


# return a dword (flags)
function parse_key_usage(data)
{
 return parse_flags(data:data);
}


function parse_extended_key_usage(data)
{ 
 local_var seq, tmp, i, oid;

 seq = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(seq) || seq[0] == 0) return NULL;

 tmp = NULL;

 for (i=0; i<seq[0]; i++)
 {
  oid = der_parse_oid(oid:seq[i+1]);
  if (isnull(oid)) return NULL;

  tmp[i] = oid;
 }

 return tmp;
}


function parse_general_name(name)
{
 local_var ret, tmp, seq;

 ret = der_decode(data:name);
 if (isnull(ret)) return NULL;

 if (! (ret[0] & 0x80) ) return NULL;

 ret[0] = ret[0] & 0x1F;

 tmp = NULL;

 if (ret[0] == 0)
   tmp["otherName"] = ret[1];

 else if (ret[0] == 1)
   tmp["rfc822Name"] = ret[1];

 else if (ret[0] == 2)
   tmp["dNSName"] = ret[1];

 else if (ret[0] == 4)
 {
  seq = der_parse_data(tag:0x30, data:ret[1]);
  if (isnull(seq)) return NULL;

  tmp["directoryName"] = parse_rdn_sequence(seq:seq);
 }

 else if (ret[0] == 6)
   tmp["uniformResourceIdentifier"] = ret[1];

 else if (ret[0] == 7)
   tmp["iPAddress"] = ret[1];

 else if (ret[0] == 8)
   tmp["registeredID"] = der_decode_oid(oid:ret[1]);

 else
 {
  display("GN: Unsupported general name!\n");
  return NULL;
 }

 return tmp;
}


function parse_general_names(names)
{
 local_var seq, tmp, i, name;

 seq = der_parse_list(list:names);
 if (isnull(seq) || seq[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<seq[0]; i++)
 {
  name = parse_general_name(name:seq[i+1]);
  if (isnull(name)) return NULL;

  tmp[i] = name;
 }

 return tmp;
}


function parse_distribution_point(dp)
{
 local_var seq, dp, ret, tmp, reasons, issuer;

 seq = der_parse_sequence(seq:dp, num:3, list:FALSE);
 if (isnull(seq)) return NULL;

 dp = reasons = issuer = NULL;

 if (!isnull(seq[0]))
 {
  ret = der_decode(data:seq[0]);
  if (isnull(ret) && ret[0] != 0xa0 && ret[0] != 0xa1) return NULL; 

  if (ret[0] == 0xa0)
    dp = parse_general_names(names:ret[1]);

#  if (ret[0] == 0xa1)
#    dp = parse_relative_distinguished_name(name:ret[1]);
 }

 if (!isnull(seq[1]))
   reasons = parse_flags(data:seq[1]);

 if (!isnull(seq[2]))
   issuer = parse_general_names(names:seq[2]);

 tmp = NULL;
 tmp["distributionPoint"] = dp;
 tmp["reasons"] = reasons;
 tmp["cRLIssuer"] = issuer;

 return tmp;
}


function parse_crl_distribution_points(data)
{
 local_var ret, tmp, i, dp;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<ret[0]; i++)
 {
  dp = parse_distribution_point(dp:ret[i+1]);
  if (isnull(dp)) return NULL;

  tmp[i] = dp;
 }

 return tmp;
}


function parse_access_description(ad)
{
 local_var ret, tmp, method, location;

 ret = der_parse_sequence(seq:ad, list:TRUE);
 if (isnull(ret) || ret[0] != 2) return NULL;
 
 method = der_parse_oid(oid:ret[1]);
 if (isnull(method)) return NULL;

 location = parse_general_name(name:ret[2]);
 if (isnull(location)) return NULL;

 tmp = NULL;
 tmp["accessMethod"] = method;
 tmp["accessLocation"] = location;

 return tmp;
}


function parse_authority_information_access(data)
{
 local_var ret, tmp, i, ad;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<ret[0]; i++)
 {
  ad = parse_access_description(ad:ret[i+1]);
  if (isnull(ad)) return NULL;

  tmp[i] = ad;
 }

 return tmp;
}


function parse_authority_key_identifier(data)
{
 local_var ret, ki, issuer, serial, tmp;

 ret = der_parse_sequence(seq:data, num:3, list:FALSE);
 if (isnull(ret)) return NULL;

 ki = issuer = serial;

 if (!isnull(ret[0]))
   ki = ret[0];

 if (!isnull(ret[1]))
   issuer = parse_general_names(names:ret[1]);

 if (!isnull(ret[2]))
   serial = ret[2];

 tmp = NULL;
 tmp["keyIdentifier"] = ki;
 tmp["authorityCertIssuer"] = issuer;
 tmp["authorityCertSerialNumber"] = serial;

 return tmp;
}


function parse_subject_key_identifier(data)
{
 return der_parse_octet_string(string:data);
}


function parse_subject_alternative_name(data)
{
 local_var ret;

 ret = der_parse_data(tag:0x30, data:data);
 if (isnull(ret)) return NULL;

 return parse_general_names(names:ret);
}


function parse_certificate_comment(data)
{
 local_var ret;

 # IA5String
 ret = der_parse_data(tag:0x16, data:data);
 if (isnull(ret)) return NULL;

 return ret;
}


function parse_policy_qualifier_information(data)
{
 local_var ret, tmp, oid, qualifier;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] != 2) return NULL;

 oid = der_parse_oid(oid:ret[1]); 
 if (isnull(oid) || (oid != OID_CPS_POINTER && oid != OID_USER_NOTICE))
   return NULL;

 if (oid == OID_CPS_POINTER)
 {
  qualifier = der_parse_data(tag:22, data:ret[2]);
  if (isnull(qualifier)) return NULL;
 }
 else if (oid == OID_USER_NOTICE)
 {
  #display("PI: Unsupported user notice!\n");
  return NULL;
 }

 tmp = NULL;
 tmp["policyQualifierId"] = oid;
 tmp["qualifier"] = qualifier;

 return tmp;
}


function parse_policy_information(data)
{
 local_var ret, tmp, oid, qualifiers, i, seq;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 oid = der_parse_oid(oid:ret[1]); 
 if (isnull(oid)) return NULL;

 qualifiers = NULL;
 if (ret[0] == 2)
 {
  seq = der_parse_sequence(seq:ret[2], list:TRUE);
  if (isnull(seq)) return NULL;

  qualifiers = NULL;
  for (i=0; i<seq[0]; i++)
    qualifiers[i] = parse_policy_qualifier_information(data:seq[i+1]);
 }

 tmp = NULL;
 tmp["policyIdentifier"] = oid;
 tmp["policyQualifiers"] = qualifiers;

 return tmp;
}


function parse_certificate_policies(data)
{
 local_var ret, tmp, i, pi;

 ret = der_parse_sequence(seq:data, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 tmp = NULL;
 for (i=0; i<ret[0]; i++)
 {
  pi = parse_policy_information(data:ret[i+1]);
  if (isnull(pi)) return NULL;

  tmp[i] = pi;
 }

 return tmp;
}


function parse_extension(extension)
{
 local_var ret, list, i, tmp, os, critical, oid;

 ret = der_parse_sequence(seq:extension, list:TRUE);
 if (isnull(ret) || ret[0] < 2) return NULL;

 oid = der_parse_oid(oid:ret[1]);
 if (isnull(oid)) return NULL;

 if (ret[0] == 2)
 {
  os = ret[2];
  critical = FALSE;
 }
 else
 {
  critical = der_parse_data(tag:0x01, data:ret[2]);
  if (ord(critical[0]) == 0)
    critical = FALSE;
  else
    critical = TRUE;

  os = ret[3];
 }

 os = der_parse_octet_string(string:os);
 if (isnull(os)) return NULL;

 if (oid == EXTN_KEY_USAGE)
   os = parse_key_usage(data:os);

 if (oid == EXTN_EXTENDED_KEY_USAGE)
   os = parse_extended_key_usage(data:os);

 if (oid == EXTN_CRL_DIST_POINTS)
   os = parse_crl_distribution_points(data:os);

 if (oid == EXTN_AUTHORITY_INFORMATION_ACCESS)
   os = parse_authority_information_access(data:os);

 if (oid == EXTN_AUTHORITY_KEY_IDENTIFIER)
   os = parse_authority_key_identifier(data:os);

 if (oid == EXTN_SUBJECT_KEY_IDENTIFIER)
   os = parse_subject_key_identifier(data:os);

 if (oid == EXTN_SUBJECT_ALTERNATIVE_NAME)
   os = parse_subject_alternative_name(data:os);

 if (oid == EXTN_CERTIFICATE_COMMENT)
   os = parse_certificate_comment(data:os);

 if (oid == EXTN_CERTIFICATE_POLICIES)
   os = parse_certificate_policies(data:os);

 extension = NULL;
 extension["extnID"] = oid;
 extension["critical"] = critical;
 extension["extnValue"] = os;

 return extension;
}


function parse_extensions(extensions)
{
 local_var ret, list, i, tmp;

 ret = der_parse_sequence(seq:extensions, list:TRUE);
 if (isnull(ret) || ret[0] == 0) return NULL;

 list = NULL;

 for (i=0; i<ret[0]; i++)
 {
  tmp = parse_extension(extension:ret[i+1]);
  if (isnull(tmp)) return NULL;

  if ( isnull(list) ) list = make_list();
  list[i] = tmp;
 }

 return list;
}


function parse_tbs_certificate(cert)
{
 local_var seq, tbs, pos, i;
 local_var tlist, tmp, ret;
 local_var serial, sig, issuer, extensions;
 local_var validity, subject, key, version;
 local_var nb, na, list;

 seq = der_decode (data:cert);
 if (isnull(seq) || (seq[0] != 0x30))
   return NULL;

 tlist = tmp = NULL;
 pos = i = 0;

 while (pos < strlen(seq[1]))
 {
  ret = der_decode (data:seq[1],pos:pos);
  if (isnull(ret))
    return NULL;
  
  if (ret[0] >= 0xa0)
    tlist[ret[0] - 0xa0] = ret[1];
  else
    tmp[i++] = ret;

  pos = ret[2];
 }

 # serialNumber
 ret = tmp[0];
 if (ret[0] != 0x02) return NULL;
 serial = ret[1];

 # signature
 ret = tmp[1];
 if (ret[0] != 0x30) return NULL;

 list = der_parse_list(list:ret[1]);
 if (isnull(list) || list[0] == 0) return NULL;

 sig = der_parse_oid(oid:list[1]);

 # issuer
 ret = tmp[2];
 if (ret[0] != 0x30) return NULL;
 issuer = parse_rdn_sequence(seq:ret[1]);
 if (isnull(issuer)) return NULL;

 # validity
 ret = tmp[3];
 if (ret[0] != 0x30) return NULL;

 list = der_parse_list(list:ret[1]);
 if (isnull(list) || list[0] != 2) return NULL;

 nb = parse_time(time:list[1]);
 if (isnull(nb)) return NULL;

 na = parse_time(time:list[2]);
 if (isnull(na)) return NULL;

 validity = NULL;
 validity["notBefore"] = nb;
 validity["notAfter"] = na;

 # subject
 ret = tmp[4];
 if (ret[0] != 0x30) return NULL;
 subject = parse_rdn_sequence(seq:ret[1]);

 # subjectPublicKeyInfo
 ret = tmp[5];
 if (ret[0] != 0x30) return NULL;
 key = parse_publickey_info(pki:ret[1]);

 # version
 version = tlist[0];
 if (isnull(version))
   version = 0;
 else
   version = der_parse_int(i:version);

 # extensions
 extensions = tlist[3];
 if ((version == 2 || version == 3) && !isnull(extensions))
   extensions = parse_extensions(extensions:extensions);

 tbs = NULL;
 tbs["version"] = version;
 tbs["serialNumber"] = serial;
 tbs["signature"] = sig;
 tbs["issuer"] = issuer;
 tbs["validity"] = validity;
 tbs["subject"] = subject;
 tbs["subjectPublicKeyInfo"] = key;
 tbs["extensions"] = extensions;

 return tbs;
}


function  parse_der_cert(cert)
{
 local_var seq, tbs, ai, sig, cert;

 seq = der_parse_sequence (seq:cert,list:TRUE);
 if (isnull(seq) || seq[0] != 3)
   return NULL;

 tbs = parse_tbs_certificate(cert:seq[1]);
 if (isnull(tbs)) return NULL;

 ai = parse_algorithm_identifier(ai:seq[2]);
 if (isnull(ai)) return NULL;

 sig = der_parse_data(tag:0x03, data:seq[3]);
 if (isnull(sig)) return NULL;

 cert = NULL;
 cert["tbsCertificate"] = tbs;
 cert["signatureAlgorithm"] = ai;
 cert["signatureValue"] = sig;

 return cert;
}


function hex_buf(buf, space)
{
 local_var len, tmp, i;

 tmp = NULL;

 len = strlen(buf);
 for (i=0;i<len;i++)
 {
  if ( (i != 0) && (i % 20) == 0 )
    tmp += '\n' + crap(data:" ", length:space);

  tmp += toupper(hexstr(buf[i])) + " ";
 }

 return tmp;
}


function add_string(name, data)
{
 return string(name, ": ", data,"\n");
}


function add_string_nl(name, data)
{
 return string(add_string(name:name, data:data), "\n");
}


function add_hex_string(name, data)
{
 local_var len;

 len = strlen(name) + 2;

 return string(name, ": ", hex_buf(buf:data, space:len),"\n");
}


function add_hex_string_nl(name, data)
{
 return string(add_hex_string(name:name, data:data), "\n");
}


function add_rdn_seq(seq)
{
 local_var tmp, name, type;

 tmp = NULL;
 if (isnull(seq)) return "";

 foreach name (seq)
 {
  type = name[0];

  if (!isnull(oid_name[type]))
    type = oid_name[type];

  tmp += add_string(name:type, data:name[1]);
 }

 return tmp;
}


function add_rdn_seq_nl(seq)
{
 return string(add_rdn_seq(seq:seq), "\n");
}


function is_known_extension(id)
{
 if (!isnull(known_extensions[id]) && known_extensions[id] == TRUE)
   return TRUE;

 return FALSE;
}


function add_extension_data(extension)
{
 if (extension["extnID"] == EXTN_KEY_USAGE)
   return add_key_usage(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_EXTENDED_KEY_USAGE)
   return add_extended_key_usage(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_CRL_DIST_POINTS)
   return add_crl_distribution_points(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_AUTHORITY_INFORMATION_ACCESS)
   return add_authority_information_access(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_AUTHORITY_KEY_IDENTIFIER)
   return add_authority_key_identifier(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_SUBJECT_KEY_IDENTIFIER)
   return add_subject_key_identifier(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_SUBJECT_ALTERNATIVE_NAME)
   return add_subject_alternative_name(data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_CERTIFICATE_COMMENT)
   return add_string_nl(name:"Comment", data:extension["extnValue"]);

 if (extension["extnID"] == EXTN_CERTIFICATE_POLICIES)
   return add_certificate_policies(data:extension["extnValue"]);

 return NULL;
}


digitalSignature        = 0x01;
nonRepudiation          = 0x02;
keyEncipherment         = 0x04;
dataEncipherment        = 0x08;
keyAgreement            = 0x10;
keyCertSign             = 0x20;
cRLSign                 = 0x40;
encipherOnly            = 0x80;
decipherOnly            = 0x100;

key_usage[digitalSignature]        = "Digital Signature";
key_usage[nonRepudiation]          = "Non Repudiation";
key_usage[keyEncipherment]         = "Key Encipherment";
key_usage[dataEncipherment]        = "Data Encipherment";
key_usage[keyAgreement]            = "Key Agreement";
key_usage[keyCertSign]             = "Key Cert Signature";
key_usage[cRLSign]                 = "CRL Signature";
key_usage[encipherOnly]            = "Encipher Only";
key_usage[decipherOnly]            = "Decipher Only";



function add_key_usage(data)
{
 local_var tmp, val, len, i, bit;

 bit = 1;
 tmp = NULL;

 while (bit <= 0x100)
 {
  if (data & bit)
  {
   if (tmp) tmp += ", ";
   
   tmp += key_usage[bit];
  }
  bit = bit << 1;
 }

 return add_string_nl(name:"Key Usage", data:tmp);
}


function add_extended_key_usage(data)
{
 local_var num, tmp, i, oid;

 num = max_index(data);
 tmp = NULL;

 for (i=0; i<num; i++)
 {
  oid = data[i];

  if (!isnull(oid_name[oid]))
    oid = string(oid_name[oid], " (", oid, ")");

  tmp += add_string(name:string("Purpose#",i+1), data:oid);
 }

 tmp += '\n';

 return tmp;
}


function add_general_name(name)
{
 local_var tmp;

 tmp = NULL;

 if (!isnull(name["directoryName"]))
   tmp += add_rdn_seq(seq:name["directoryName"]);

 if (!isnull(name["otherName"]))
   tmp += add_hex_string(name:"Other Name", data:name["otherName"]);

 if (!isnull(name["dNSName"]))
   tmp += add_string(name:"DNS", data:name["dNSName"]);

 if (!isnull(name["uniformResourceIdentifier"]))
   tmp += add_string(name:"URI", data:name["uniformResourceIdentifier"]);

 return tmp;
}


function add_crl_distribution_points(data)
{
 local_var dp, tmp, p, name;

 tmp = NULL;

 foreach dp (data)
 {
  p = dp["distributionPoint"];
  foreach name (p)
    tmp += add_general_name(name:name);
 }

 tmp += '\n';

 return tmp;
}


function add_authority_information_access(data)
{
 local_var tmp, num, i, ad, name, method;

 tmp = NULL;
 num = max_index(data);

 for (i=0; i<num; i++)
 {
  ad = data[i];

  method = ad["accessMethod"];
  if (!isnull(oid_name[method]))
    method = oid_name[method];

  tmp += add_string(name:string("Method","#",i+1), data:method);

  name = ad["accessLocation"];
  tmp += add_general_name(name:name);
 }

 tmp += '\n';

 return tmp;
}


function add_authority_key_identifier(data)
{
 local_var tmp, issuer, name;

 tmp = NULL;

 if (!isnull(data["keyIdentifier"]))
   tmp += add_hex_string(name:"Key Identifier", data:data["keyIdentifier"]);

 if (!isnull(data["authorityCertIssuer"]))
 {
  issuer = data["authorityCertIssuer"];
  foreach name (issuer)
    tmp += add_general_name(name:name);
 }

 if (!isnull(data["authorityCertSerialNumber"]))
   tmp += add_hex_string(name:"Serial Number", data:data["authorityCertSerialNumber"]);

 tmp += '\n';

 return tmp;
}


function add_subject_key_identifier(data)
{
 return add_hex_string_nl(name:"Subject Key Identifier", data:data);
}


function add_subject_alternative_name(data)
{
 local_var name, tmp;

 tmp = NULL;

 foreach name (data)
   tmp += add_general_name(name:name);

 tmp += '\n';

 return tmp;
}


function add_certificate_policies(data)
{
 local_var num, i, tmp, policy, pq, qualifier, qi, oid;

 tmp = NULL;

 num = max_index(data);
 for (i=0; i<num; i++)
 {
  policy = data[i];
  tmp += add_string(name:string("Policy ID #",i+1), data:policy["policyIdentifier"]);

  pq = policy["policyQualifiers"];
  foreach qi (pq)
  {
   oid = qi["policyQualifierId"];
   tmp += add_string(name:string("Qualifier ID #",i+1), data:string(oid_name[oid], " (", oid, ")"));
   
   qualifier = qi["qualifier"];
   if (qi["policyQualifierId"] == OID_CPS_POINTER)
     tmp += add_string(name:"CPS URI", data:qualifier);
  }
 }

 tmp += '\n';

 return tmp;
}


function dump_certificate(cert)
{
 local_var tbs, subject, report, issuer, validity, pki;
 local_var key, extensions, extension, name;

 tbs = cert["tbsCertificate"];

 subject = tbs["subject"];

 report += add_string_nl(name:"Subject Name", data:"") +
           add_rdn_seq_nl(seq:subject);

 issuer = tbs["issuer"];

 report += add_string_nl(name:"Issuer Name", data:"") +
           add_rdn_seq_nl(seq:issuer);

 report += add_hex_string_nl(name:"Serial Number", data:tbs["serialNumber"]) +
           add_string_nl(name:"Version", data:tbs["version"]+1) +
           add_string_nl(name:"Signature Algorithm", data:oid_name[tbs["signature"]]);

 validity = tbs["validity"];

 report += add_string(name:"Not Valid Before", data:validity["notBefore"]) +
           add_string_nl(name:"Not Valid After", data:validity["notAfter"]) ;

 pki = tbs["subjectPublicKeyInfo"];
 key = pki[1];

 report += add_string_nl(name:"Public Key Info", data:"") +
           add_string(name:"Algorithm", data:oid_name[pki[0]]) +
           add_hex_string(name:"Public Key", data:key[0]) +
           add_hex_string_nl(name:"Exponent", data:key[1]) ;

 report += add_hex_string_nl(name:"Signature", data:cert["signatureValue"]) ;


 extensions = tbs["extensions"];
 if (!isnull(extensions))
 { 
  foreach extension (extensions)
  {
   name = extension["extnID"];
   if (!isnull(oid_name[name]))
     name = string(oid_name[name], " (", name, ")");

   report += add_string(name:"Extension", data:name) +
             add_string(name:"Critical", data:extension["critical"]) ;

   if (is_known_extension(id:extension["extnID"]))
     report += add_extension_data(extension:extension);
   else
     report += add_hex_string_nl(name:"Data", data:extension["extnValue"]);

   report += '\n';
  }
 }

 return report;
}

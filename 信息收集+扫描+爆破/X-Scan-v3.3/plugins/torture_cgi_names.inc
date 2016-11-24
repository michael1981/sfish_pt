# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# torture_cgi_names.inc
# $Revision: 1.3 $
#

function torture_cgi_name(code)
{
  global_var	_torture_cgi_names;

  if (isnull(_torture_cgi_names))
    _torture_cgi_names = make_array(
      "XS", "cross-site scripting", 
      "FS", "format string",
      "PX", "persistent XSS",
      "WI", "web code injection",
      "HI", "header injection",
      "DD", "data disclosure",
      "DT", "directory traversal",
      "EX", "arbitrary command execution",
      "SI", "SQL injection",
      "II", "SSI injection",
      "IH", "SSI injection (on HTTP headers)",
      "BS", "blind SQL injection",
      "SH", "SQL injection (on HTTP headers)",
      "SC", "SQL injection (on HTTP cookies)",
      "LI", "local file injection",
      "LD", "LDAP injection",
      "RS", "HTTP response splitting");

  if (isnull(_torture_cgi_names[code])) return code;
  return  _torture_cgi_names[code];
}

#
# (C) Tenable Network Security, Inc.
#
# This script contains information extracted from VuXML :
#
# Copyright 2003-2006 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#   copyright notice, this list of conditions and the following
#   disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#   published online in any format, converted to PDF, PostScript,
#   RTF and other formats) must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer
#   in the documentation and/or other materials provided with the
#   distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#

include('compat.inc');

if ( description )
{
 script_id(19346);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(14106);
 script_cve_id("CVE-2005-2088");

 script_name(english:"FreeBSD : apache -- http request smuggling (1770)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: apache+ipv6');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.watchfire.com/resources/HTTP-Request-Smuggling.pdf');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/651996e0-fe07-11d9-8329-000e0c2e438a.html');

 script_end_attributes();
 script_summary(english:"Check for apache+ipv6");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}
global_var cvss_score;
cvss_score=4;
include('freebsd_package.inc');


holes_nb += pkg_test(pkg:"apache<1.3.33_2");

holes_nb += pkg_test(pkg:"apache>2.*<2.0.54_1");

holes_nb += pkg_test(pkg:"apache>2.1.0<2.1.6_1");

holes_nb += pkg_test(pkg:"apache+ssl<1.3.33.1.55_1");

holes_nb += pkg_test(pkg:"apache+mod_perl<1.3.33_3");

holes_nb += pkg_test(pkg:"apache+mod_ssl<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+ipv6<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_accel<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_accel+ipv6<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_accel+mod_deflate<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_deflate<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_deflate+ipv6<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_snmp<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_snmp+mod_accel<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_snmp+mod_deflate<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6<1.3.33+2.8.22_1");

holes_nb += pkg_test(pkg:"apache+ipv6<1.3.37");

holes_nb += pkg_test(pkg:"ru-apache<1.3.34+30.22");

holes_nb += pkg_test(pkg:"ru-apache+mod_ssl<1.3.34+30.22+2.8.25");

if (holes_nb == 0) exit(0,"Host is not affected");

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
 script_id(22208);
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(18092);
 script_cve_id("CVE-2006-2313", "CVE-2006-2314");

 script_name(english:"FreeBSD : postgresql -- encoding based SQL injection (1389)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: ja-postgresql');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.postgresql.org/docs/techdocs.50');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/17f53c1d-2ae9-11db-a6e2-000e0c2e438a.html');

 script_end_attributes();
 script_summary(english:"Check for ja-postgresql");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}
global_var cvss_score;
cvss_score=7;
include('freebsd_package.inc');


holes_nb += pkg_test(pkg:"postgresql>=7.3<7.3.15");

holes_nb += pkg_test(pkg:"postgresql>=7.4<7.4.13");

holes_nb += pkg_test(pkg:"postgresql>=8.0.0<8.0.8");

holes_nb += pkg_test(pkg:"postgresql>=8.1.0<8.1.4");

holes_nb += pkg_test(pkg:"postgresql-server>=7.3<7.3.15");

holes_nb += pkg_test(pkg:"postgresql-server>=7.4<7.4.13");

holes_nb += pkg_test(pkg:"postgresql-server>=8.0.0<8.0.8");

holes_nb += pkg_test(pkg:"postgresql-server>=8.1.0<8.1.4");

holes_nb += pkg_test(pkg:"ja-postgresql>=7.3<7.3.15");

holes_nb += pkg_test(pkg:"ja-postgresql>=7.4<7.4.13");

holes_nb += pkg_test(pkg:"ja-postgresql>=8.0.0<8.0.8");

holes_nb += pkg_test(pkg:"ja-postgresql>=8.1.0<8.1.4");

if (holes_nb == 0) exit(0,"Host is not affected");

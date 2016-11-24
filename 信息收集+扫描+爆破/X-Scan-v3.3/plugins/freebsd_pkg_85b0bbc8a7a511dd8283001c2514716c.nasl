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
 script_id(34686);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(31928);

 script_name(english:"FreeBSD : phpmyadmin -- Cross-Site Scripting Vulnerability (1951)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: phpMyAdmin211');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.hornik.sk/SA/SA-20040802.txt
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-14.html
http://www.mozilla.org/security/announce/2006/mfsa2006-15.html
http://www.mozilla.org/security/announce/2006/mfsa2006-16.html
http://www.mozilla.org/security/announce/2006/mfsa2006-17.html
http://www.mozilla.org/security/announce/2006/mfsa2006-18.html
http://www.mozilla.org/security/announce/2006/mfsa2006-19.html
http://www.mozilla.org/security/announce/2006/mfsa2006-20.html
http://www.mozilla.org/security/announce/2006/mfsa2006-22.html
http://www.mozilla.org/security/announce/2006/mfsa2006-23.html
http://www.mozilla.org/security/announce/2006/mfsa2006-25.html
http://www.mozilla.org/security/announce/2006/mfsa2006-26.html
http://www.mozilla.org/security/announce/2006/mfsa2006-28.html
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-9');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/85b0bbc8-a7a5-11dd-8283-001c2514716c.html');

 script_end_attributes();
 script_cve_id("CVE-2008-4775");
 script_summary(english:"Check for phpMyAdmin211");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}
global_var cvss_score;
cvss_score=10;
include('freebsd_package.inc');


holes_nb += pkg_test(pkg:"phpMyAdmin>3.0<3.0.1.1");

holes_nb += pkg_test(pkg:"phpMyAdmin<2.11.9.3");

holes_nb += pkg_test(pkg:"phpMyAdmin211<2.11.9.3");

if (holes_nb == 0) exit(0,"Host is not affected");

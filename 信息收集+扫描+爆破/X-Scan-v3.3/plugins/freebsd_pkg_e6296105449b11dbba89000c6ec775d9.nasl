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
 script_id(22350);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(20042);
 script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4568", "CVE-2006-4569", "CVE-2006-4570", "CVE-2006-4571");

 script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (2387)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: firefox');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/security/announce/2006/mfsa2006-57.html
http://www.mozilla.org/security/announce/2006/mfsa2006-58.html
http://www.mozilla.org/security/announce/2006/mfsa2006-59.html
http://www.mozilla.org/security/announce/2006/mfsa2006-60.html
http://www.mozilla.org/security/announce/2006/mfsa2006-61.html
http://www.mozilla.org/security/announce/2006/mfsa2006-62.html
http://www.mozilla.org/security/announce/2006/mfsa2006-63.html
http://www.mozilla.org/security/announce/2006/mfsa2006-64.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/e6296105-449b-11db-ba89-000c6ec775d9.html');

 script_end_attributes();
 script_summary(english:"Check for firefox");
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


holes_nb += pkg_test(pkg:"firefox<1.5.0.7,1");

holes_nb += pkg_test(pkg:"firefox>2.*,1<2.0_1,1");

holes_nb += pkg_test(pkg:"linux-firefox<1.5.0.7");

holes_nb += pkg_test(pkg:"seamonkey<1.0.5");

holes_nb += pkg_test(pkg:"linux-seamonkey<1.0.5");

holes_nb += pkg_test(pkg:"thunderbird<1.5.0.7");

holes_nb += pkg_test(pkg:"linux-thunderbird<1.5.0.7");

holes_nb += pkg_test(pkg:"mozilla-thunderbird<1.5.0.7");

holes_nb += pkg_test(pkg:"linux-firefox-devel<3.0.a2006.09.21");

holes_nb += pkg_test(pkg:"linux-seamonkey-devel<1.5.a2006.09.21");

if (holes_nb == 0) exit(0,"Host is not affected");

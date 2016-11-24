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
 script_id(19345);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");

 script_name(english:"FreeBSD : firefox &amp; mozilla -- multiple vulnerabilities (1730)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: firefox');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/projects/security/known-vulnerabilities.html
http://www.mozilla.org/security/announce/mfsa2005-45.html
http://www.mozilla.org/security/announce/mfsa2005-46.html
http://www.mozilla.org/security/announce/mfsa2005-47.html
http://www.mozilla.org/security/announce/mfsa2005-48.html
http://www.mozilla.org/security/announce/mfsa2005-49.html
http://www.mozilla.org/security/announce/mfsa2005-50.html
http://www.mozilla.org/security/announce/mfsa2005-51.html
http://www.mozilla.org/security/announce/mfsa2005-52.html
http://www.mozilla.org/security/announce/mfsa2005-53.html
http://www.mozilla.org/security/announce/mfsa2005-54.html
http://www.mozilla.org/security/announce/mfsa2005-55.html
http://www.mozilla.org/security/announce/mfsa2005-56.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/5d72701a-f601-11d9-bcd1-02061b08fc24.html');

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
cvss_score=7;
include('freebsd_package.inc');


holes_nb += pkg_test(pkg:"firefox<1.0.5,1");

holes_nb += pkg_test(pkg:"linux-firefox<1.0.5");

holes_nb += pkg_test(pkg:"mozilla<1.7.9,2");

holes_nb += pkg_test(pkg:"linux-mozilla<1.7.9");

holes_nb += pkg_test(pkg:"linux-mozilla-devel<1.7.9");

if (holes_nb == 0) exit(0,"Host is not affected");

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
 script_id(31155);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");

 script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (1922)");

script_set_attribute(attribute:'synopsis', value: 'The remote host is missing a security update');
script_set_attribute(attribute:'description', value:'The following package needs to be updated: firefox');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute:'solution', value: 'Update the package on the remote host');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/projects/security/known-vulnerabilities.html
http://www.mozilla.org/security/announce/2008/mfsa2008-01.html
http://www.mozilla.org/security/announce/2008/mfsa2008-02.html
http://www.mozilla.org/security/announce/2008/mfsa2008-03.html
http://www.mozilla.org/security/announce/2008/mfsa2008-04.html
http://www.mozilla.org/security/announce/2008/mfsa2008-05.html
http://www.mozilla.org/security/announce/2008/mfsa2008-06.html
http://www.mozilla.org/security/announce/2008/mfsa2008-07.html
http://www.mozilla.org/security/announce/2008/mfsa2008-08.html
http://www.mozilla.org/security/announce/2008/mfsa2008-09.html
http://www.mozilla.org/security/announce/2008/mfsa2008-10.html
http://www.mozilla.org/security/announce/2008/mfsa2008-11.html');
script_set_attribute(attribute:'see_also', value: 'http://www.FreeBSD.org/ports/portaudit/810a5197-e0d9-11dc-891a-02061b08fc24.html');

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
cvss_score=9;
include('freebsd_package.inc');


holes_nb += pkg_test(pkg:"firefox<2.0.0.12,1");

holes_nb += pkg_test(pkg:"linux-firefox<2.0.0.12");

holes_nb += pkg_test(pkg:"seamonkey<1.1.8");

holes_nb += pkg_test(pkg:"linux-seamonkey<1.1.8");

holes_nb += pkg_test(pkg:"flock<1.0.9");

holes_nb += pkg_test(pkg:"linux-flock<1.0.9");

if (holes_nb == 0) exit(0,"Host is not affected");

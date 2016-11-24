#
# (C) Tenable Network Security
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
 seealso  = '\n';


include("compat.inc");

if ( description )
{
 script_id(12581);
 script_version("$Revision: 1.6 $");

 script_name(english:"FreeBSD : mplayer heap overflow in http requests (120)");


 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing an update to the system

The following package is affected: mplayer-esound" );
 script_set_attribute(attribute:"solution", value:
"Update the package on the remote host" );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();

 script_summary(english:"Check for mplayer-esound");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"mplayer<0.92.1",
     url:"http://www.FreeBSD.org/ports/portaudit/5e7f58c3-b3f8-4258-aeb8-795e5e940ff8.html",
     problem:'mplayer heap overflow in http requests',
     seealso:seealso);

pkg_test(pkg:"mplayer-gtk<0.92.1",
     url:"http://www.FreeBSD.org/ports/portaudit/5e7f58c3-b3f8-4258-aeb8-795e5e940ff8.html",
     problem:'mplayer heap overflow in http requests',
     seealso:seealso);

pkg_test(pkg:"mplayer-esound<0.92.1",
     url:"http://www.FreeBSD.org/ports/portaudit/5e7f58c3-b3f8-4258-aeb8-795e5e940ff8.html",
     problem:'mplayer heap overflow in http requests',
     seealso:seealso);

pkg_test(pkg:"mplayer-gtk-esound<0.92.1",
     url:"http://www.FreeBSD.org/ports/portaudit/5e7f58c3-b3f8-4258-aeb8-795e5e940ff8.html",
     problem:'mplayer heap overflow in http requests',
     seealso:seealso);

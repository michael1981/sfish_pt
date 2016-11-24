# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(31386);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-11");
 script_cve_id("CVE-2007-5718");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-11
(Vobcopy: Insecure temporary file creation)


    Joey Hess reported that vobcopy appends data to the file
    "/tmp/vobcopy.bla" in an insecure manner.
  
Impact

    A local attacker could exploit this vulnerability to conduct symlink
    attacks and append data to arbitrary files with the privileges of the
    user running Vobcopy.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Vobcopy users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vobcopy-1.1.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5718');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-11] Vobcopy: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Vobcopy: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/vobcopy", unaffected: make_list("ge 1.1.0"), vulnerable: make_list("lt 1.1.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

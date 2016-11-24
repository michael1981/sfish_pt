# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-08.xml
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
 script_id(17274);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200503-08");
 script_cve_id("CVE-2005-0605");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-08
(OpenMotif, LessTif: New libXpm buffer overflows)


    Chris Gilbert discovered potentially exploitable buffer overflow
    cases in libXpm that weren\'t fixed in previous libXpm security
    advisories.
  
Impact

    A carefully-crafted XPM file could crash applications making use
    of the OpenMotif or LessTif toolkits, potentially allowing the
    execution of arbitrary code with the privileges of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenMotif users should upgrade to an unaffected version:
    # emerge --sync
    # emerge --ask --oneshot --verbose x11-libs/openmotif
    All LessTif users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/lesstif-0.94.0-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0605');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-08] OpenMotif, LessTif: New libXpm buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenMotif, LessTif: New libXpm buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/openmotif", unaffected: make_list("ge 2.2.3-r3", "rge 2.1.30-r9"), vulnerable: make_list("lt 2.2.3-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-libs/lesstif", unaffected: make_list("ge 0.94.0-r2"), vulnerable: make_list("lt 0.94.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

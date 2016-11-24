# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-06.xml
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
 script_id(29293);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200712-06");
 script_cve_id("CVE-2007-4992", "CVE-2007-5246");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-06
(Firebird: Multiple buffer overflows)


    Adriano Lima and Ramon de Carvalho Valle reported that functions
    isc_attach_database() and isc_create_database() do not perform proper
    boundary checking when processing their input.
  
Impact

    A remote attacker could send specially crafted requests to the Firebird
    server on TCP port 3050, possibly resulting in the execution of
    arbitrary code with the privileges of the user running Firebird
    (usually firebird).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Firebird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/firebird-2.0.3.12981.0-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4992');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5246');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-06] Firebird: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Firebird: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/firebird", unaffected: make_list("ge 2.0.3.12981.0-r2"), vulnerable: make_list("lt 2.0.3.12981.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");

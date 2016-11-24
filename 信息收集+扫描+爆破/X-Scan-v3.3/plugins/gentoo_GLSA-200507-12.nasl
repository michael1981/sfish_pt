# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-12.xml
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
 script_id(19199);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200507-12");
 script_cve_id("CVE-2005-2173", "CVE-2005-2174");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-12
(Bugzilla: Unauthorized access and information disclosure)


    Bugzilla allows any user to modify the flags of any bug
    (CAN-2005-2173). Bugzilla inserts bugs into the database before marking
    them as private, in connection with MySQL replication this could lead
    to a race condition (CAN-2005-2174).
  
Impact

    By manually changing the URL to process_bug.cgi, a remote attacker
    could modify the flags of any given bug, which could trigger an email
    including the bug summary to be sent to the attacker. The race
    condition when using Bugzilla with MySQL replication could lead to a
    short timespan (usually less than a second) where the summary of
    private bugs is exposed to all users.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Bugzilla users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/bugzilla-2.18.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2173');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2174');
script_set_attribute(attribute: 'see_also', value: 'http://www.bugzilla.org/security/2.18.1/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-12] Bugzilla: Unauthorized access and information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Bugzilla: Unauthorized access and information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/bugzilla", unaffected: make_list("ge 2.18.3"), vulnerable: make_list("lt 2.18.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

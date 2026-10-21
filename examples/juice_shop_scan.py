"""
R3X Example: Automated Assessment on OWASP Juice Shop or Test Environment
Demonstrates programmatic usage of R3X-BugBounty.
"""
from r3x.memory.db import db
from r3x.agents.hermes_master import hermes_master
from r3x.reports.generator import report_generator

def main():
    target_url = "https://juice-shop.herokuapp.com"
    project_name = "owasp-juice-shop-audit"

    print(f"Initializing R3X Security Assessment for {target_url}...")

    # 1. Setup project
    p = db.create_project("proj-juice-1", project_name, "OWASP Juice Shop Audit Demo")
    db.add_target("target-juice-1", p["id"], target_url, "juice-shop.herokuapp.com")
    db.set_scope(
        scope_id="scope-juice-1",
        project_id=p["id"],
        domain="juice-shop.herokuapp.com",
        allowed=["juice-shop.herokuapp.com"],
        excluded=["*.gov", "logout", "delete"]
    )

    # 2. Run scan
    results = hermes_master.execute_scan(
        target_url=target_url,
        project_name=project_name,
        scan_type="quick"
    )

    # 3. Export report
    report_file = report_generator.create_report(
        project_id=p["id"],
        format_type="html"
    )
    print(f"Audit completed. Report generated: {report_file}")

if __name__ == "__main__":
    main()

-- nightly payroll export
USE PayrollDB;
SELECT e.emp_ssn, e.full_name, p.net_amount
FROM hr.employees e
JOIN payroll_runs p ON p.employee_id = e.id
WHERE e.email = 'dana.whitfield@contoso.com' AND p.run_date > '2026-09-30';

INSERT INTO audit_payroll_access (accessed_by, reason) VALUES ('kchen', 'quarter close');
EXEC dbo.usp_RecalcBonuses @Year = 2026;
-- connection: Server=sqlprod02.contoso.local;Database=PayrollDB;User Id=svc_payroll;Password=Hunter2!x;
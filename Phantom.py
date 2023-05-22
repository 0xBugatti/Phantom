import array

from flask import Flask, render_template, request
import re

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        php_code = request.files['php_file'].read().decode('utf-8')
        vulnerabilities = analyze_code(php_code)
        return render_template('dashboard.html', vulnerabilities=vulnerabilities)

    return render_template('index.html')


def analyze_code(code):
    vulnerabilities = []
    vulnerabilities.extend(detect_xss(code))
    vulnerabilities.extend(detect_sql_injection(code))
    vulnerabilities.extend(detect_lfi(code))
    vulnerabilities.extend(detect_unrestricted_file_upload(code))
    vulnerabilities.extend(detect_os_command_injection(code))
    vulnerabilities.extend(detect_ssrf(code))
    return vulnerabilities


#Final XSS
def detect_xss(php_code):
    vulnerable_lines = ["XSS"]
    pattern = r'(?:echo|print(_r)?|printf|sprintf|vprintf|vfprintf|htmlentities|htmlspecialchars|strip_tags|addcslashes|addslashes|rawurlencode|urlencode|urldecode)\s*(?:\$[^\s]+\s*\.\s*|htmlspecialchars\([^)]*?\)\s*\.\s*)*[^;]+'

    lines = php_code.split('\n')
    for line_num, line in enumerate(lines, start=1):
        if re.search(pattern, line):
            vulnerable_lines.append((line_num, line.strip()))

    return vulnerable_lines
def detect_sql_injection(php_code):
    vulnerable_lines = ["SQL"]
    lines = php_code.split("\n")

    for i, line in enumerate(lines):
        if re.search(r'\$.*->\b(?:query|exec|prepare|mysqli_query|mysqli_prepare|mysql_query|mysql_db_query|mysql_unbuffered_query|pg_query|pg_query_params|pg_prepare|pg_send_query|pg_send_query_params|pg_send_prepare|sqlite_query|sqlite_exec|sqlite_array_query|oci_parse|oci_execute|oci_bind_by_name|odbc_prepare|odbc_exec|odbc_execute)\b.*\$_(GET|POST)\b', line) or \
                re.search(r'\bmysql(?:i)?_.*\b(?:query|exec|prepare)\b.*\$_(GET|POST)\b', line):
            vulnerable_lines.append( line)
        elif re.search(r'\$.*=.*->\b(?:query|exec|prepare|mysqli_query|mysqli_prepare|mysql_query|mysql_db_query|mysql_unbuffered_query|pg_query|pg_query_params|pg_prepare|pg_send_query|pg_send_query_params|pg_send_prepare|sqlite_query|sqlite_exec|sqlite_array_query|oci_parse|oci_execute|oci_bind_by_name|odbc_prepare|odbc_exec|odbc_execute)\b', line) or \
                re.search(r'\$.*=.*\bmysql(?:i)?_.*\b(?:query|exec|prepare)\b', line):
            query_variable = re.findall(r'\$(\w+)', line)
            if query_variable:
                query_variable = query_variable[0]
                vulnerable_lines.append(str("("+i.__str__() +", " +line))
    return vulnerable_lines



def detect_lfi(php_code):

        vulnerable_lines = ["LFI"]
        lines = php_code.split("\n")

        for i, line in enumerate(lines):
            if re.search(r'\binclude\b.*\$\w+\b', line) or \
                    re.search(r'\brequire(?:_once)?\b.*\$\w+\b', line) or \
                    re.search(r'\binclude[_once]?[ (].*["\']\s*\.\s*\$\w+\b', line) or \
                    re.search(r'\brequire[_once]?[ (].*["\']\s*\.\s*\$\w+\b', line):
                vulnerable_lines.append(str("("+i.__str__() +", " +line))

        return vulnerable_lines





def detect_unrestricted_file_upload(code):
    file_upload_regex = r"(?i)\b(move_uploaded_file|copy)\b"
    matches = re.finditer(file_upload_regex, code)
    vulnerable_lines = ["Unrestricted File Upload"]
    vulnerable_lines.append([{"line_number": get_line_number(code, match.start()), "line_content": get_line_content(code, match.start())} for match in matches])
    return vulnerable_lines




def detect_os_command_injection(php_code):
    vulnerable_lines = ["OS Command Injection"]
    lines = php_code.split("\n")

    for i, line in enumerate(lines):
        if re.search(r'\bexec\b.*\$_(GET|POST)\b', line) or \
           re.search(r'\bsystem\b.*\$_(GET|POST)\b', line) or \
           re.search(r'\bshell_exec\b.*\$_(GET|POST)\b', line) or \
           re.search(r'\bpassthru\b.*\$_(GET|POST)\b', line) or \
           re.search(r'\bproc_open\b.*\$_(GET|POST)\b', line) or \
           re.search(r'\bexec\b.*["\']\s*\.\s*\$\w+\b', line) or \
           re.search(r'\bsystem\b.*["\']\s*\.\s*\$\w+\b', line) or \
           re.search(r'\bshell_exec\b.*["\']\s*\.\s*\$\w+\b', line) or \
           re.search(r'\bpassthru\b.*["\']\s*\.\s*\$\w+\b', line) or \
           re.search(r'\bproc_open\b.*["\']\s*\.\s*\$\w+\b', line):
            vulnerable_lines.append((i + 1, line))

    return vulnerable_lines


def detect_ssrf(code):
    ssrf_regex = r"(?i)\b(curl|file_get_contents|fopen|readfile)\b"
    matches = re.finditer(ssrf_regex, code)
    vulnerable_lines = [{"line_number": get_line_number(code, match.start()), "line_content": get_line_content(code, match.start())} for match in matches]
    return "SSRF" ,vulnerable_lines





def get_line_number(code, index):
    lines = code[:index + 1].count("\n") + 1
    return lines

def get_line_content(code, index):
    start = code.rfind("\n", 0, index) + 1
    end = code.find("\n", index)
    return code[start:end]

if __name__ == '__main__':
    app.run()
    print(vulnerable_lines)

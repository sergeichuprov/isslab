# instructor_api.py
from flask import Flask, request, jsonify

app = Flask(__name__)

# The SECRET packets, which the students never see.
secret_packets = [
    {'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.50', 'dst_port': 80, 'protocol': 'TCP', 'expected': 'ACCEPT'},
    {'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.50', 'dst_port': 23, 'protocol': 'TCP', 'expected': 'DROP'},
    {'src_ip': '203.0.113.123', 'dst_ip': '192.168.1.50', 'dst_port': 22, 'protocol': 'TCP', 'expected': 'ACCEPT'},
    {'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.50', 'dst_port': 22, 'protocol': 'TCP', 'expected': 'DROP'},
    {'src_ip': '198.51.100.5', 'dst_ip': '192.168.1.50', 'dst_port': 443, 'protocol': 'TCP', 'expected': 'DROP'},
    {'src_ip': '8.8.8.8', 'dst_ip': '192.168.1.50', 'dst_port': 9999, 'protocol': 'UDP', 'expected': 'DROP'},
]

@app.route('/evaluate', methods=['POST'])
def evaluate():
    student_data = request.get_json()
    student_ruleset = student_data['ruleset']
    student_logic_str = student_data['logic_function']

    # This is a safe way to execute the student's function string
    exec_globals = {}
    exec(student_logic_str, exec_globals)
    student_check_firewall = exec_globals['check_firewall']

    # Evaluate the student's logic against the secret packets
    correct_decisions = 0
    total_packets = len(secret_packets)

    for packet in secret_packets:
        decision = student_check_firewall(packet, student_ruleset)
        if decision == packet['expected']:
            correct_decisions += 1
    
    score_message = (f"Your firewall made {correct_decisions} out of "
                     f"{total_packets} correct decisions.")

    return jsonify({"message": score_message})

if __name__ == '__main__':
    # You would run this on your server using a production-ready server like Gunicorn
    app.run(host='0.0.0.0', port=80)
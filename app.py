import os
import sys
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, abort
from werkzeug.utils import safe_join
import threading
from threading import Lock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from vulnbot.scanner import NmapScanner
from vulnbot.shodan_api import ShodanClient
from vulnbot.cve_mapper import CVEMapper
from vulnbot.reporter import Reporter
from vulnbot.config import Config
from vulnbot.validator import InputValidator

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET', os.urandom(24).hex())

scan_status = {}
scan_history = []
scan_lock = Lock()
history_lock = Lock()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json or {}
    target = data.get('target')
    ports = data.get('ports', '1-1000')
    use_shodan = data.get('use_shodan', True)
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    valid_target, target_msg = InputValidator.validate_target(target)
    if not valid_target:
        return jsonify({'error': f'Invalid target: {target_msg}'}), 400
    
    valid_ports, ports_msg = InputValidator.validate_ports(ports)
    if not valid_ports:
        return jsonify({'error': f'Invalid ports: {ports_msg}'}), 400
    
    target = InputValidator.sanitize_target(target)
    ports = InputValidator.sanitize_ports(ports)
    
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    with scan_lock:
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 'Initializing scan...',
            'target': target
        }
    
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, target, ports, use_shodan)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})


def run_scan(scan_id, target, ports, use_shodan):
    try:
        with scan_lock:
            scan_status[scan_id]['progress'] = 'Running Nmap scan...'
        
        scanner = NmapScanner()
        scan_results = scanner.scan_target(target=target, ports=ports)
        
        if not scan_results:
            with scan_lock:
                scan_status[scan_id] = {
                    'status': 'error',
                    'error': 'Scan failed or no results'
                }
            return
        
        if use_shodan:
            try:
                with scan_lock:
                    scan_status[scan_id]['progress'] = 'Enriching with Shodan data...'
                
                shodan_client = ShodanClient()
                scan_results = shodan_client.enrich_scan_results(scan_results)
                
                with scan_lock:
                    scan_status[scan_id]['progress'] = 'Mapping CVEs...'
                
                cve_mapper = CVEMapper()
                scan_results = cve_mapper.map_vulnerabilities(scan_results)
            except Exception as e:
                with scan_lock:
                    scan_status[scan_id]['progress'] = f'Shodan/CVE enrichment failed: {str(e)}'
        
        with scan_lock:
            scan_status[scan_id]['progress'] = 'Generating reports...'
        
        reporter = Reporter()
        reports = reporter.generate_reports(scan_results, target)
        
        with history_lock:
            scan_history.append({
                'scan_id': scan_id,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'hosts': len(scan_results.get('hosts', [])),
                'vulnerabilities': sum(len(h.get('vulnerabilities', [])) for h in scan_results.get('hosts', [])),
                'reports': reports
            })
        
        with scan_lock:
            scan_status[scan_id] = {
                'status': 'completed',
                'results': scan_results,
                'reports': reports
            }
        
    except Exception as e:
        with scan_lock:
            scan_status[scan_id] = {
                'status': 'error',
                'error': str(e)
            }


@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    with scan_lock:
        if scan_id not in scan_status:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(scan_status[scan_id])


@app.route('/api/history')
def get_history():
    with history_lock:
        return jsonify(scan_history[::-1])


@app.route('/api/report/<path:filename>')
def download_report(filename):
    try:
        base_dir = os.path.abspath('reports')
        
        if '..' in filename or filename.startswith('/'):
            abort(403)
        
        file_path = safe_join(base_dir, filename)
        
        if file_path is None:
            abort(403)
        
        real_path = os.path.realpath(file_path)
        real_base = os.path.realpath(base_dir)
        
        if not real_path.startswith(real_base + os.sep):
            abort(403)
        
        if not os.path.exists(real_path):
            return jsonify({'error': 'Report not found'}), 404
        
        if not os.path.isfile(real_path):
            abort(403)
        
        return send_file(real_path)
    except Exception:
        abort(403)


@app.route('/api/config')
def get_config():
    valid, message = Config.validate()
    return jsonify({
        'shodan_configured': valid,
        'message': message
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

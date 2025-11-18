#!/usr/bin/env python3
"""
SecOps Helper Web Dashboard
A Flask-based web interface for all SecOps Helper tools
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from iocExtractor.extractor import IOCExtractor
from hashLookup.lookup import HashLookup
from domainIpIntel.intel import IntelligenceGatherer
from logAnalysis.analyzer import LogAnalyzer
from emlAnalysis.emlParser import EMLParser
from common.stix_export import export_to_stix
from common.cache_manager import get_cache

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['SECRET_KEY'] = os.urandom(24)

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'eml': {'.eml', '.msg'},
    'ioc': {'.txt', '.md', '.log', '.json'},
    'log': {'.log', '.txt'},
    'pcap': {'.pcap', '.pcapng', '.cap'},
    'hash': {'.txt', '.csv'}
}


def allowed_file(filename, file_type):
    """Check if file extension is allowed for the given tool type"""
    if '.' not in filename:
        return False
    ext = '.' + filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS.get(file_type, set())


@app.route('/')
def index():
    """Render main dashboard page"""
    return render_template('index.html')


@app.route('/api/ioc/extract', methods=['POST'])
def extract_iocs():
    """
    Extract IOCs from text input or file

    Request JSON:
        {
            "text": "text to analyze",
            "types": ["ip", "domain", "url", "email", "hash", "cve"],
            "defang": false,
            "exclude_private_ips": true,
            "format": "json"
        }

    Returns:
        JSON with extracted IOCs
    """
    try:
        data = request.get_json() or {}
        text = data.get('text', '')

        # Handle file upload
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename, 'ioc'):
                text = file.read().decode('utf-8', errors='ignore')

        if not text:
            return jsonify({'error': 'No text or file provided'}), 400

        # Extract IOCs
        types = data.get('types', ['all'])
        defang = data.get('defang', False)
        exclude_private = data.get('exclude_private_ips', True)
        output_format = data.get('format', 'json')

        extractor = IOCExtractor(
            defang=defang,
            refang=False,
            exclude_private_ips=exclude_private
        )

        results = extractor.extract_from_text(text, types=types)

        # Calculate statistics
        total_iocs = sum([
            len(results.get('ips', [])),
            len(results.get('domains', [])),
            len(results.get('urls', [])),
            len(results.get('emails', [])),
            sum(len(h) for h in results.get('hashes', {}).values()),
            len(results.get('cves', []))
        ])

        response = {
            'success': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'statistics': {
                'total_iocs': total_iocs,
                'ips': len(results.get('ips', [])),
                'domains': len(results.get('domains', [])),
                'urls': len(results.get('urls', [])),
                'emails': len(results.get('emails', [])),
                'hashes': sum(len(h) for h in results.get('hashes', {}).values()),
                'cves': len(results.get('cves', []))
            },
            'results': results
        }

        # STIX export if requested
        if output_format == 'stix':
            stix_output = export_to_stix(results, output_type='simple')
            response['stix'] = json.loads(stix_output)

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hash/lookup', methods=['POST'])
def lookup_hashes():
    """
    Look up file hashes against threat intelligence sources

    Request JSON:
        {
            "hashes": ["hash1", "hash2", ...],
            "sources": ["virustotal", "malwarebazaar"]
        }

    Returns:
        JSON with hash lookup results
    """
    try:
        data = request.get_json() or {}
        hashes = data.get('hashes', [])

        if isinstance(hashes, str):
            hashes = [h.strip() for h in hashes.split('\n') if h.strip()]

        if not hashes:
            return jsonify({'error': 'No hashes provided'}), 400

        lookup = HashLookup()
        results = []

        for hash_value in hashes:
            result = lookup.lookup(hash_value.strip())
            if result:
                results.append(result)

        # Calculate statistics
        verdicts = {'malicious': 0, 'suspicious': 0, 'clean': 0, 'unknown': 0}
        for r in results:
            verdict = r.get('verdict', 'unknown')
            verdicts[verdict] = verdicts.get(verdict, 0) + 1

        response = {
            'success': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'statistics': {
                'total_hashes': len(results),
                'verdicts': verdicts
            },
            'results': results
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/intel/analyze', methods=['POST'])
def analyze_intelligence():
    """
    Analyze domains or IP addresses

    Request JSON:
        {
            "targets": ["8.8.8.8", "example.com", ...],
            "sources": ["virustotal", "abuseipdb"]
        }

    Returns:
        JSON with intelligence analysis results
    """
    try:
        data = request.get_json() or {}
        targets = data.get('targets', [])

        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split('\n') if t.strip()]

        if not targets:
            return jsonify({'error': 'No targets provided'}), 400

        intel = IntelligenceGatherer()
        results = []

        for target in targets:
            result = intel.analyze(target.strip())
            if result:
                results.append(result)

        # Calculate statistics
        risk_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        for r in results:
            classification = r.get('classification', 'unknown')
            risk_levels[classification] = risk_levels.get(classification, 0) + 1

        response = {
            'success': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'statistics': {
                'total_targets': len(results),
                'risk_levels': risk_levels
            },
            'results': results
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/log/analyze', methods=['POST'])
def analyze_logs():
    """
    Analyze security logs

    Request: multipart/form-data with file upload or JSON with log_text

    Returns:
        JSON with log analysis results
    """
    try:
        log_text = None
        log_type = request.form.get('log_type', 'auto')

        # Handle file upload
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename, 'log'):
                # Save to temp file
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
                file.save(temp_path)

                analyzer = LogAnalyzer()
                results = analyzer.analyze_file(temp_path, log_type=log_type)

                # Clean up temp file
                os.remove(temp_path)

                response = {
                    'success': True,
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'statistics': results.get('statistics', {}),
                    'alerts': results.get('alerts', []),
                    'top_ips': results.get('top_ips', []),
                    'top_paths': results.get('top_paths', [])
                }

                return jsonify(response)

        # Handle JSON text input
        data = request.get_json() or {}
        log_text = data.get('log_text', '')

        if not log_text:
            return jsonify({'error': 'No log file or text provided'}), 400

        # Write to temp file for analysis
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_log_{os.getpid()}.log')
        with open(temp_path, 'w') as f:
            f.write(log_text)

        analyzer = LogAnalyzer()
        results = analyzer.analyze_file(temp_path, log_type=log_type)

        os.remove(temp_path)

        response = {
            'success': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'statistics': results.get('statistics', {}),
            'alerts': results.get('alerts', []),
            'top_ips': results.get('top_ips', []),
            'top_paths': results.get('top_paths', [])
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/eml/parse', methods=['POST'])
def parse_email():
    """
    Parse and analyze email files

    Request: multipart/form-data with .eml file

    Returns:
        JSON with email analysis results
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if not file or not allowed_file(file.filename, 'eml'):
            return jsonify({'error': 'Invalid file type. Expected .eml file'}), 400

        # Save to temp file
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(temp_path)

        # Parse email
        use_vt = request.form.get('use_virustotal', 'false').lower() == 'true'
        parser = EMLParser(use_virustotal=use_vt)
        results = parser.parse(temp_path)

        # Clean up
        os.remove(temp_path)

        response = {
            'success': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'results': results
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })


@app.route('/api/cache/stats', methods=['GET'])
def get_cache_stats():
    """Get cache statistics"""
    try:
        cache = get_cache()
        stats = cache.get_stats()

        # Add namespace-specific stats
        namespaces = cache.get_namespaces()
        namespace_stats = {}
        for ns in namespaces:
            namespace_stats[ns] = cache.get_stats(namespace=ns)

        return jsonify({
            'success': True,
            'overall': stats,
            'namespaces': namespace_stats,
            'health': cache.health_check()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear cache (specific namespace or all)"""
    try:
        data = request.get_json() or {}
        namespace = data.get('namespace')

        cache = get_cache()

        if namespace:
            deleted = cache.clear_namespace(namespace)
            message = f"Cleared {deleted} keys from namespace '{namespace}'"
        else:
            cache.clear_all()
            message = "Cleared entire cache"

        return jsonify({
            'success': True,
            'message': message
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    # Get cache stats
    cache_stats = {}
    try:
        cache = get_cache()
        cache_stats = cache.get_stats()
    except:
        pass

    stats = {
        'total_analyses': 1234,
        'iocs_extracted': 5678,
        'hashes_looked_up': 890,
        'logs_analyzed': 456,
        'emails_parsed': 123,
        'uptime': '99.9%',
        'cache': cache_stats
    }
    return jsonify(stats)


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 50MB'}), 413


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )

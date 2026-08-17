import sqlite3, os, glob
import xml.etree.ElementTree as ET

DB_PATH = '../corpus.db'
XML_DIR = '../results/cbmc_out'

def parse_one(xml_path):
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        results = root.findall('.//result')
        if not results:
            return 'INCONCLUSIVE', None
        for r in results:
            if r.get('status') == 'FAILURE':
                return 'SAT', r.get('property', '')
        return 'UNSAT', None
    except ET.ParseError:
        return 'PARSE_ERROR', None

def run():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    n = 0
    for xml_path in glob.glob(f'{XML_DIR}/*.xml'):
        pid = int(os.path.basename(xml_path).replace('.xml', ''))
        verdict, prop = parse_one(xml_path)
        cursor.execute('''INSERT OR REPLACE INTO formal_results
                           (program_id, cbmc_result, violated_property)
                           VALUES (?, ?, ?)''', (pid, verdict, prop))
        n += 1
    conn.commit()
    print(f"Parsed {n} CBMC XML files into formal_results.")
    cursor.execute("SELECT cbmc_result, COUNT(*) FROM formal_results GROUP BY cbmc_result")
    print(cursor.fetchall())

if __name__ == "__main__":
    run()

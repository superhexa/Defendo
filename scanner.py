import hashlib
import pefile
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import zlib
from datetime import datetime

class MalwareScanner:
    def __init__(self, hash_files):
        self.hashes = set(line.strip().lower() for file in hash_files for line in open(file))
        self.types = {'md5', 'sha1', 'sha256', 'sha512'}

    def _calculate_hash(self, file_path, hash_type):
        h = hashlib.new(hash_type)
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest().lower()
        except FileNotFoundError:
            return None

    def _calculate_crc32(self, file_path):
        crc = 0
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    crc = zlib.crc32(chunk, crc)
            return crc & 0xFFFFFFFF
        except FileNotFoundError:
            return None

    def _scan_file(self, file_path):
        hashes = {hash_type: self._calculate_hash(file_path, hash_type) for hash_type in self.types}
        crc32 = self._calculate_crc32(file_path)
        infected = any(h in self.hashes for h in hashes.values() if h)

        try:
            pe = pefile.PE(file_path)
            characteristics = {
                'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
                'SectionNames': [s.Name.decode().strip() for s in pe.sections],
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'EntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
                'ImportedDLLs': [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],
                'ExportedFunctions': [symbol.name.decode() for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],
                'ResourceEntries': [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries] if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else [],
                'DigitalSignature': 'Signed' if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 'Not Signed'
            }
        except pefile.PEFormatError:
            characteristics = {'DigitalSignature': 'Not a PE file'}

        file_stats = os.stat(file_path)
        permissions = oct(file_stats.st_mode)[-3:]
        return {
            'file_path': file_path,
            'hashes': hashes,
            'crc32': crc32,
            'infected': infected,
            'size': os.path.getsize(file_path) if infected else None,
            'creation_time': datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'modification_time': datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'permissions': permissions,
            'number_of_sections': characteristics.get('NumberOfSections'),
            'section_names': characteristics.get('SectionNames'),
            'image_base': characteristics.get('ImageBase'),
            'entry_point': characteristics.get('EntryPoint'),
            'size_of_image': characteristics.get('SizeOfImage'),
            'imported_dlls': characteristics.get('ImportedDLLs'),
            'exported_functions': characteristics.get('ExportedFunctions'),
            'resource_entries': characteristics.get('ResourceEntries'),
            'digital_signature': characteristics.get('DigitalSignature')
        }

    def scan_files(self, file_paths):
        results = []
        with ThreadPoolExecutor() as executor:
            future_to_file = {executor.submit(self._scan_file, file_path): file_path for file_path in file_paths}
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append({'file_path': file_path, 'infected': False, 'analysis': f"Error: {e}"})
        return results

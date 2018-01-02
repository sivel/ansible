# Copyright (c), Matt Martz <matt@sivel.net> 2017
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

import os

AVAILABLE_HASH_ALGORITHMS = dict()
try:
    import hashlib

    # python 2.7.9+ and 2.7.0+
    for attribute in ('available_algorithms', 'algorithms'):
        algorithms = getattr(hashlib, attribute, None)
        if algorithms:
            break
    if algorithms is None:
        # python 2.5+
        algorithms = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
    for algorithm in algorithms:
        AVAILABLE_HASH_ALGORITHMS[algorithm] = getattr(hashlib, algorithm)
except ImportError:
    import sha
    AVAILABLE_HASH_ALGORITHMS = {'sha1': sha.sha}
    try:
        import md5
        AVAILABLE_HASH_ALGORITHMS['md5'] = md5.md5
    except ImportError:
        pass


class DummyClass(object):
    def digest_from_file(self, filename, algorithm):
        ''' Return hex digest of local file for a digest_method specified by name, or None if file is not present. '''
        if not os.path.exists(filename):
            return None
        if os.path.isdir(filename):
            self.fail_json(msg="attempted to take checksum of directory: %s" % filename)

        # preserve old behaviour where the third parameter was a hash algorithm object
        if hasattr(algorithm, 'hexdigest'):
            digest_method = algorithm
        else:
            try:
                digest_method = AVAILABLE_HASH_ALGORITHMS[algorithm]()
            except KeyError:
                self.fail_json(msg="Could not hash file '%s' with algorithm '%s'. Available algorithms: %s" %
                                   (filename, algorithm, ', '.join(AVAILABLE_HASH_ALGORITHMS)))

        blocksize = 64 * 1024
        infile = open(os.path.realpath(filename), 'rb')
        block = infile.read(blocksize)
        while block:
            digest_method.update(block)
            block = infile.read(blocksize)
        infile.close()
        return digest_method.hexdigest()

    def md5(self, filename):
        ''' Return MD5 hex digest of local file using digest_from_file().

        Do not use this function unless you have no other choice for:
            1) Optional backwards compatibility
            2) Compatibility with a third party protocol

        This function will not work on systems complying with FIPS-140-2.

        Most uses of this function can use the module.sha1 function instead.
        '''
        if 'md5' not in AVAILABLE_HASH_ALGORITHMS:
            raise ValueError('MD5 not available.  Possibly running in FIPS mode')
        return self.digest_from_file(filename, 'md5')

    def sha1(self, filename):
        ''' Return SHA1 hex digest of local file using digest_from_file(). '''
        return self.digest_from_file(filename, 'sha1')

    def sha256(self, filename):
        ''' Return SHA-256 hex digest of local file using digest_from_file(). '''
        return self.digest_from_file(filename, 'sha256')

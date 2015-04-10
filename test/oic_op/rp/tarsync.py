import os

__author__ = 'roland'

from oictest.oprp import create_tar_archive

for iss in os.listdir("log"):
    _dir = os.path.join("log", iss)
    for profile in os.listdir(_dir):
        create_tar_archive(iss, profile)

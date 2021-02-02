#for entropy
import numpy as np
from scipy.stats import entropy
from math import log, e
import pandas as pd

#for url parsing
from urllib.parse import urlparse


def splitdomain(url):
    parse_object = urlparse(url)
    base = parse_object.netloc
    path = parse_object.path
    scheme = parse_object.scheme

    return base, path, scheme


def percentage(part, whole):
    return 100 * float(part)/float(whole)


def entropy(labels, base=2):
    """ Computes entropy of label distribution. """

    n_labels = len(labels)

    if n_labels <= 1:
        return 0

    value,counts = np.unique(labels, return_counts=True)
    probs = counts / n_labels
    n_classes = np.count_nonzero(probs)

    if n_classes <= 1:
        return 0

    ent = 0.

    # Compute entropy
    base = e if base is None else base
    for i in probs:
        ent -= i * log(i, base)

    return ent



print("Starting...")



# Step 2. Open the list of domains, line by line, in to a dictionary object
import csv

with open('Phishstats.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for line in csv_reader:
        score = line[1]
        url = line[2]
        ip = line[3]
        domain, uri, scheme = splitdomain(url)
        ent = entropy(list(domain))

        print(f"{domain} score = {score}, entropy = {ent}")



print("Finished.")

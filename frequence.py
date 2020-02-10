# -*- coding: utf-8 -*-
import sys

def hist(text):
    total = len(text)
    freq = dict()

    for c in text:
        if c in freq:
            freq[c] += 1
        else:
            freq[c] = 1
    
    for key in freq.keys():
        freq[key] /= (total*1.0)

    return freq

def hist_from_file(path):
    try:
        with open(path) as f:
            txt = f.readlines()
            s = ""
            for i in range(len(txt)):
                s += txt[i].replace('\n', '')

            s = s.replace(' ', '')
            return hist(s)
    except FileNotFoundError:
        print(path + " not found")
        return None
    except IOError:
        print("File is not readable")
        return None

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Usage: python frequence.py file_path")

    res_dict = hist_from_file(sys.argv[1])
    keys = sorted(res_dict.keys())
    for key in keys:
        print(str(key) + " " + str(res_dict[key]))

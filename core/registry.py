# registry.py — سجل الوحدات: قلب النظام
MODULES = {}          # name -> (category, desc, fn)
CATEGORIES = {}       # category -> [names]

def module(name, category, desc):
    def deco(fn):
        MODULES[name] = (category, desc, fn)
        CATEGORIES.setdefault(category, []).append(name)
        return fn
    return deco

def run(name, target, args, R):
    return MODULES[name][2](target, args, R)

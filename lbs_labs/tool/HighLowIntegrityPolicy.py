# Integrity Policy: High-Low
# H = Trusted (Clean)
# L = Untrusted (Tainted)
# Flow: H -> L (Trusted can flow to Untrusted)
# Lattice: H <= L (H is Bottom, L is Top)

class HighLowIntegrityPolicy():
    
    def __init__(self):
        pass
    
    def get_sec_classes(self):
        return {'L', 'H'}
    
    def can_flow(self, label_1, label_2):
        return label_1 == "H" or label_2 == "L"
    
    def glb(self, label_1, label_2):
        if label_1 == "L" and label_2 == "L":
            return "L"
        return "H"
    
    def lub(self, label_1, label_2):
        if label_1 == "L" or label_2 == "L":
            return "L"
        return "H"

    def bottom(self): 
        return "H" # trusted
    
    def top(self): 
        return "L"    # untrusted
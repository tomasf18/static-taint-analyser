class HighLowConfidentialityPolicy():
    
    def __init__(self):
        pass
    
    def get_sec_classes(self):
        return {'L', 'H'}
    
    def can_flow(self, label_1, label_2):
        return label_1=="L" or label_2=="H"
    
    def glb(self, label_1, label_2):
        if label_1=="L" or label_2=="L":
            return "L"
        else:
            return "H"
        
    def lub(self, label_1, label_2):
        if label_1=="H" or label_2=="H":
            return "H"
        else:
            return "L"
    
    def bottom(self):
        return "L"
    
    def top(self):
        return "H"
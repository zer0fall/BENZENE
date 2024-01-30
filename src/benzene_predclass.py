class PredClassBase():
    def __init__(self, op_name, constant=None):
        self.op_name = op_name
        self.constant = constant
        return

    def operate(self, values):
        return None

    def get_verbose(self, neg=False):
        return 'None'

    def get_alpha(self):
        return self.constant
        

class PredClassExist(PredClassBase):
    def __init__(self, op_name, constant):
        super().__init__(op_name, constant=constant)
        return

    def operate(self, values):
        if len(values) == 0:
            return False
        if self.constant in values:
            return True
        else:
            return False        
        
    def get_verbose(self, neg=False):
        if not neg:
            return "exist(%s,0x%x)" % (self.op_name, self.constant)
        else:
            return "~exist(%s,0x%x)" % (self.op_name, self.constant)

class PredClassGEQ(PredClassBase): 
    # all values are greater-or-equal than self.constant
    def __init__(self, op_name, constant):
        super().__init__(op_name, constant=constant)
        return

    def operate(self, values):
        if len(values) == 0:
            return False
        if min(values) >= self.constant: # greater-or-equal
            return True
        else:
            return False       
        
    def get_verbose(self, neg=False):
        if not neg:
            return "geq(%s,0x%x)" % (self.op_name, self.constant)
        else:
            return "less_exist(%s,0x%x)" % (self.op_name, self.constant)


class PredClassLEQ(PredClassBase):
    def __init__(self, op_name, constant):
        super().__init__(op_name, constant=constant)
        return

    def operate(self, values):
        if len(values) == 0: return False

        if max(values) <= self.constant:
            return True
        else:
            return False  
        
    def get_verbose(self, neg=False):
        if not neg:
            return "leq(%s,0x%x)" % (self.op_name, self.constant)
        else:
            return "greater_exist(%s,0x%x)" % (self.op_name, self.constant)

# class PredClassGEQSigned(PredClassBase): 
#     # all values are greater-or-equal than self.constant
#     def __init__(self, op_name, constant, size):
#         super().__init__(op_name, constant=self.convert_signdness(constant))
#         self.size = size
#         return

#     def operate(self, values):
#         if len(values) == 0: return False        
            
#         singed_values = [self.convert_signdness(v).value for v in values]

#         if min(singed_values) >= self.constant: # greater-or-equal
#             return True
#         else:
#             return False            
        
#     def convert_signdness(self, c):
#         if self.size == 8:
#             return ctypes.c_int64(c)
#         elif self.size == 4:
#             return ctypes.c_int32(c)
#         elif self.size == 2:
#             return ctypes.c_short(c)           
#         elif self.size == 1:
#             return ctypes.c_byte(c)      

#     def get_verbose(self):
#         return "geq_signed(%s,0x%x)" % (self.op_name, self.constant)

#     def get_verbose_not(self):
#         return "leq_exist_signed(%s, 0x%x)" % (self.op_name, self.constant)


# class PredClassLEQSigned(PredClassBase): 
#     # all values are greater-or-equal than self.constant
#     def __init__(self, op_name, constant, size):
#         super().__init__(op_name, constant=self.convert_signdness(constant))
#         self.size = size
#         return

#     def operate(self, values):
#         if len(values) == 0: return False        
            
#         singed_values = [self.convert_signdness(v).value for v in values]

#         if max(singed_values) <= self.constant:
#             return True
#         else:
#             return False         
        
#     def convert_signdness(self, c):
#         if self.size == 8:
#             return ctypes.c_int64(c)
#         elif self.size == 4:
#             return ctypes.c_int32(c)
#         elif self.size == 2:
#             return ctypes.c_short(c)           
#         elif self.size == 1:
#             return ctypes.c_byte(c)      

#     def get_verbose(self):
#         return "leq_signed(%s,0x%x)" % (self.op_name, self.constant)

#     def get_verbose_not(self):
#         return "geq_exist_signed(%s, 0x%x)" % (self.op_name, self.constant)



# class PredClassExec(PredClassBase):
#     def __init__(self, op_name):
#         super().__init__(op_name)
#         return

#     def operate(self, values):
#         if len(values) == 0: return False
#         else:
#             return True
        
#     def get_verbose(self, neg=False):
#         return "executed(%s)" % (self.op_name)



class PredClassPtrExist(PredClassBase):
    def __init__(self, op_name, range):
        super().__init__(op_name)

        self.ptr_min = range[0]
        self.ptr_max = range[1]

        return

    def operate(self, values):
        if len(values) == 0:
            return False
        
        for v in values:
            if v >= self.ptr_min and v <= self.ptr_max:
                return True
        
        return False
        
    def get_verbose(self, neg=False):
        if neg == False:
            return "ptr_exist(%s)" % (self.op_name)
        else:
            return "only_const(%s)" % (self.op_name)


class PredClassConstExist(PredClassBase):
    def __init__(self, op_name, range):
        super().__init__(op_name)

        self.ptr_min = range[0]
        self.ptr_max = range[1]

        return

    def operate(self, values):
        if len(values) == 0:
            return False

        for v in values:
            if v < self.ptr_min or v > self.ptr_max:
                return True
        
        return False
        
    def get_verbose(self, neg=False):
        if neg == False:
            return "const_exist(%s)" % (self.op_name)
        else:
            return "only_ptr(%s)" % (self.op_name)
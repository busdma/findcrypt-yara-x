import idaapi
import idautils
import ida_bytes
import ida_diskio
import idc
import yara_x
import os
import glob

YARARULES_CFGFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findcrypt3.yar")

try:
    class Kp_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.widget_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET

    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1
except:
    pass

p_initialized = False

class YaraSearchResultChooser(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Rules file", idaapi.Choose.CHCOL_PLAIN|12],
                ["Name", idaapi.Choose.CHCOL_PLAIN|25],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class Findcrypt_Plugin_t(idaapi.plugin_t):
    comment = "Findcrypt plugin for IDA Pro (using yara-x framework)"
    help = "todo"
    wanted_name = "Findcrypt"
    wanted_hotkey = "Ctrl-Alt-F"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Searcher.register(self, "Findcrypt")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            self.user_directory = self.get_user_directory()
            idaapi.register_action(idaapi.action_desc_t(
                "Findcrypt",
                "Find crypto constants",
                Searcher(),
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Search", "Findcrypt", idaapi.SETMENU_APP)
            print("=" * 80)
            print("YARA-X support for Findcrypt, tested on IDA Pro 8.4")
            print("Findcrypt search shortcut key is Ctrl-Alt-F")
            print("Global rules in %s" % YARARULES_CFGFILE)
            print("User-defined rules in %s/*.yar" % self.user_directory)
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def toVirtualAddress(self, offset, segments):
        va_offset = 0
        for seg in segments:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset

    def get_user_directory(self):
        user_dir = ida_diskio.get_user_idadir()
        plug_dir = os.path.join(user_dir, "plugins")
        res_dir = os.path.join(plug_dir, "findcrypt-yara-x")
        if not os.path.exists(res_dir):
            os.makedirs(res_dir, 0o755)
        return res_dir
    
    def get_rules_files(self):
        yield YARARULES_CFGFILE
        for fpath in glob.glob(os.path.join(self.user_directory, "*.yar")):
            yield fpath

    def get_compiled_rules(self):
        compiler = yara_x.Compiler()
        for path in self.get_rules_files():
            try:
                compiler.add_source(open(path).read())
            except Exception as e:
                print(f"Error compiling rule file {path}: {e}")
        return compiler.build()

    def search(self):
        memory, offsets = self._get_memory()
        rules = self.get_compiled_rules()
        values = self.yarasearch(memory, offsets, rules)
        c = YaraSearchResultChooser("Findcrypt results", values)
        c.show()

    def yarasearch(self, memory, offsets, rules):
        print(">>> start yara-x search")
        values = []
        result = rules.scan(memory)
        rows = [
            (rule.identifier, rule.namespace, match.offset) 
            for rule in result.matching_rules 
            for pattern in rule.patterns
            for match in pattern.matches
        ]
        for row in rows:
            identifier, namespace, offset = row
            va = self.toVirtualAddress(offset, offsets)
            if identifier.endswith("_API"):
                try:
                    name = idc.get_strlit_contents(va)
                    identifier = f"{identifier}_{name.decode()}"
                except:
                    pass
            values.append([
                va,
                namespace,
                f"{identifier}_{va:X}",
            ])
            if idaapi.get_name(va) == "":
                idaapi.set_name(va, f"{identifier}_{va:X}", 0)
        print("<<< end yara-x search")
        return values

    def _get_memory(self):
        result = bytearray()
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_attr(start, idc.SEGATTR_END)
            result += ida_bytes.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return bytes(result), offsets

    def run(self, arg):
        self.search()

# register IDA plugin
def PLUGIN_ENTRY():
    return Findcrypt_Plugin_t()

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formatting.rule import CellIsRule

def build_workbook(out_path):
    wb = openpyxl.Workbook()

    # Colors & Styles
    header_fill = PatternFill("solid", fgColor="1F4E78")
    subhdr_fill = PatternFill("solid", fgColor="D9E1F2")
    cat6_blu_fill = PatternFill("solid", fgColor="E8F1FA")
    cat6_yel_fill = PatternFill("solid", fgColor="FFF9DB")
    rg6_fill = PatternFill("solid", fgColor="F2F2F2")
    done_fill = PatternFill("solid", fgColor="C6EFCE")

    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    title_font = Font(name="Calibri", size=14, bold=True, color="1F4E78")
    bold_font = Font(name="Calibri", size=11, bold=True)
    reg_font = Font(name="Calibri", size=11)
    check_font = Font(name="Calibri", size=12, bold=True)

    thin = Side(border_style="thin", color="BFBFBF")
    med_bottom = Side(border_style="medium", color="1F4E78")
    border_all = Border(left=thin, right=thin, top=thin, bottom=thin)
    border_group_end = Border(left=thin, right=thin, top=thin, bottom=med_bottom)

    center = Alignment(horizontal="center", vertical="center", wrap_text=True)
    left = Alignment(horizontal="left", vertical="center", wrap_text=True)

    # =========================================================================
    # SHEET 1: Wire-by-Wire Checklist
    # =========================================================================
    ws1 = wb.active
    ws1.title = "Wire-by-Wire Checklist"
    ws1.views.sheetView[0].showGridLines = True

    ws1["A1"] = "Cooney Residence (1901 W. Oakdale) — TV Wire Pull & Termination Checklist"
    ws1["A1"].font = title_font
    ws1.merge_cells("A1:L1")

    ws1["A2"] = "Tip: Type 'x' or 'Yes' (or use the dropdown) in the check-off columns as you complete each wire. Green highlight activates automatically."
    ws1["A2"].font = Font(name="Calibri", size=10, italic=True, color="595959")
    ws1.merge_cells("A2:I2")

    ws1["J2"] = "Pulled Progress:"
    ws1["J2"].font = bold_font
    ws1["J2"].alignment = Alignment(horizontal="right", vertical="center")
    ws1["K2"] = '=COUNTIF(H5:H33, "<>") & " / " & COUNTA(D5:D33) & " Wires"'
    ws1["K2"].font = bold_font
    ws1["K2"].alignment = center
    ws1["K2"].fill = subhdr_fill

    headers_1 = [
        "Floor",
        "Sheet",
        "Room / TV Location",
        "TV ID",
        "Wire ID",
        "Cable Type & Color",
        "Head End (HE)",
        "Pulled\n[x]",
        "Term. at TV\n[x]",
        "Term. at HE\n[x]",
        "Tested\n[x]",
        "Notes / Footage"
    ]

    ws1.row_dimensions[4].height = 28
    for col_idx, text in enumerate(headers_1, start=1):
        cell = ws1.cell(row=4, column=col_idx, value=text)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = center
        cell.border = border_all

    wires = [
        # Lower Level - TV-007 Office
        ("Lower Level", "1/7", "Office (006)", "TV-007", "NW-013", "CAT 6 (BLU)", "SW HE", True),
        ("Lower Level", "1/7", "Office (006)", "TV-007", "CBL-006", "RG-6 Coax (BLK)", "SW HE", False),

        # Lower Level - TV-001 Game Room North
        ("Lower Level", "1/7", "Game Room (003) - North Wall TV", "TV-001", "NW-001", "CAT 6 (BLU)", "SW HE", False),
        ("Lower Level", "1/7", "Game Room (003) - North Wall TV", "TV-001", "NW-002", "CAT 6 (BLU)", "SW HE", False),
        ("Lower Level", "1/7", "Game Room (003) - North Wall TV", "TV-001", "VD-001", "CAT 6-(S) Shielded (YEL)", "Rack", False),
        ("Lower Level", "1/7", "Game Room (003) - North Wall TV", "TV-001", "CBL-001", "RG-6 Coax (BLK)", "SW HE", True),

        # Lower Level - TV-002 Game Room Center
        ("Lower Level", "1/7", "Game Room (003) - Center Display", "TV-002", "NW-003", "CAT 6 (BLU)", "SW HE", False),
        ("Lower Level", "1/7", "Game Room (003) - Center Display", "TV-002", "NW-004", "CAT 6 (BLU)", "SW HE", False),
        ("Lower Level", "1/7", "Game Room (003) - Center Display", "TV-002", "VD-002", "CAT 6-(S) Shielded (YEL)", "Rack", True),

        # 1st Floor - Outdoor Patio / Pergola TV
        ("1st Floor", "3/7", "Outdoor Patio / Pergola (North, by Sport Court 108)", "TV (VD-007)", "NW-014", "CAT 6 (BLU)", "SW HE", False),
        ("1st Floor", "3/7", "Outdoor Patio / Pergola (North, by Sport Court 108)", "TV (VD-007)", "NW-015", "CAT 6 (BLU)", "SW HE", False),
        ("1st Floor", "3/7", "Outdoor Patio / Pergola (North, by Sport Court 108)", "TV (VD-007)", "VD-007", "CAT 6-(S) Shielded (YEL)", "SW HE", False),
        ("1st Floor", "3/7", "Outdoor Patio / Pergola (North, by Sport Court 108)", "TV (VD-007)", "CBL-007", "RG-6 Coax (BLK)", "SW HE", True),

        # 1st Floor - West Fireplace / Family Room (105)
        ("1st Floor", "3/7", "Family Room (105) - West Fireplace (by Kitchen 104)", "TV (VD-003)", "NW-005", "CAT 6 (BLU)", "SW HE", False),
        ("1st Floor", "3/7", "Family Room (105) - West Fireplace (by Kitchen 104)", "TV (VD-003)", "NW-006", "CAT 6 (BLU)", "SW HE", False),
        ("1st Floor", "3/7", "Family Room (105) - West Fireplace (by Kitchen 104)", "TV (VD-003)", "VD-003", "CAT 6-(S) Shielded (YEL)", "SW HE", False),
        ("1st Floor", "3/7", "Family Room (105) - West Fireplace (by Kitchen 104)", "TV (VD-003)", "CBL-002", "RG-6 Coax (BLK)", "SW HE", True),

        # 1st Floor - East Fireplace / Living Room (102)
        ("1st Floor", "3/7", "Living Room (102) - East Fireplace (by Dining 102)", "TV (VD-004)", "NW-007", "CAT 6 (BLU)", "SW HE", False),
        ("1st Floor", "3/7", "Living Room (102) - East Fireplace (by Dining 102)", "TV (VD-004)", "NW-008", "CAT 6 (BLU)", "SW HE", False),
        ("1st Floor", "3/7", "Living Room (102) - East Fireplace (by Dining 102)", "TV (VD-004)", "VD-004", "CAT 6-(S) Shielded (YEL)", "AV Closet", False),
        ("1st Floor", "3/7", "Living Room (102) - East Fireplace (by Dining 102)", "TV (VD-004)", "CBL-003", "RG-6 Coax (BLK)", "SW HE", True),

        # 2nd Floor - Kids' Suite (207)
        ("2nd Floor", "5/7", "Kids' Suite (207) - East Wall", "TV (VD-006)", "NW-011", "CAT 6 (BLU)", "SW HE", False),
        ("2nd Floor", "5/7", "Kids' Suite (207) - East Wall", "TV (VD-006)", "NW-012", "CAT 6 (BLU)", "SW HE", False),
        ("2nd Floor", "5/7", "Kids' Suite (207) - East Wall", "TV (VD-006)", "VD-006", "CAT 6-(S) Shielded (YEL)", "AV Closet", False),
        ("2nd Floor", "5/7", "Kids' Suite (207) - East Wall", "TV (VD-006)", "CBL-005", "RG-6 Coax (BLK)", "SW HE", True),

        # 2nd Floor - Main Bedroom (203)
        ("2nd Floor", "5/7", "Main Bedroom (203) - East Wall Fireplace", "TV (VD-005)", "NW-009", "CAT 6 (BLU)", "SW HE", False),
        ("2nd Floor", "5/7", "Main Bedroom (203) - East Wall Fireplace", "TV (VD-005)", "NW-010", "CAT 6 (BLU)", "SW HE", False),
        ("2nd Floor", "5/7", "Main Bedroom (203) - East Wall Fireplace", "TV (VD-005)", "VD-005", "CAT 6-(S) Shielded (YEL)", "AV Closet", False),
        ("2nd Floor", "5/7", "Main Bedroom (203) - East Wall Fireplace", "TV (VD-005)", "CBL-004", "RG-6 Coax (BLK)", "SW HE", True),
    ]

    start_row = 5
    for idx, (floor, sheet, room, tv_id, wire_id, ctype, he, is_group_end) in enumerate(wires):
        r = start_row + idx
        ws1.row_dimensions[r].height = 22
        vals = [floor, sheet, room, tv_id, wire_id, ctype, he, "", "", "", "", ""]

        if "BLU" in ctype:
            row_fill = cat6_blu_fill
        elif "YEL" in ctype:
            row_fill = cat6_yel_fill
        else:
            row_fill = rg6_fill

        bdr = border_group_end if is_group_end else border_all

        for c_idx, val in enumerate(vals, start=1):
            cell = ws1.cell(row=r, column=c_idx, value=val)
            cell.border = bdr
            if c_idx in (5, 6):
                cell.fill = row_fill
                cell.font = bold_font if c_idx == 5 else reg_font
            elif c_idx in (8, 9, 10, 11):
                cell.font = check_font
                cell.alignment = center
            else:
                cell.font = reg_font
            if c_idx in (1, 2, 4, 5, 7):
                cell.alignment = center
            elif c_idx in (3, 6, 12):
                cell.alignment = left

    # Dropdown validation for check-off columns H:K
    dv = DataValidation(type="list", formula1='"✓,x,Yes,N/A"', allow_blank=True)
    ws1.add_data_validation(dv)
    dv.add(f"H5:K{start_row + len(wires) - 1}")

    # Conditional formatting: turn cell green when non-empty in H5:K33
    green_rule = CellIsRule(operator="notEqual", formula=['""'], stopIfTrue=True, fill=done_fill)
    ws1.conditional_formatting.add(f"H5:K{start_row + len(wires) - 1}", green_rule)

    ws1.freeze_panes = "A5"
    ws1.auto_filter.ref = f"A4:L{start_row + len(wires) - 1}"

    col_widths_1 = [14, 8, 44, 14, 12, 26, 14, 12, 13, 13, 12, 28]
    for i, w in enumerate(col_widths_1, start=1):
        ws1.column_dimensions[get_column_letter(i)].width = w

    # =========================================================================
    # SHEET 2: By TV Location Summary
    # =========================================================================
    ws2 = wb.create_sheet(title="By TV Location Summary")
    ws2.views.sheetView[0].showGridLines = True

    ws2["A1"] = "Cooney Residence — Summary Checklist by TV Location"
    ws2["A1"].font = title_font
    ws2.merge_cells("A1:K1")

    ws2["H2"] = "Locations Pulled:"
    ws2["H2"].font = bold_font
    ws2["H2"].alignment = Alignment(horizontal="right", vertical="center")
    ws2["I2"] = '=COUNTIF(I5:I12, "<>") & " / 8 TVs"'
    ws2["I2"].font = bold_font
    ws2["I2"].alignment = center
    ws2["I2"].fill = subhdr_fill

    headers_2 = [
        "Floor",
        "Sheet",
        "Room / TV Location",
        "TV ID",
        "Blue CAT 6\n(Data/Network)",
        "Yellow CAT 6-(S)\n(Shielded Video)",
        "RG-6 Coax",
        "Head End (HE)",
        "All Wires Pulled\n[x]",
        "Trimmed & Tested\n[x]",
        "Notes"
    ]

    ws2.row_dimensions[4].height = 28
    for col_idx, text in enumerate(headers_2, start=1):
        cell = ws2.cell(row=4, column=col_idx, value=text)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = center
        cell.border = border_all

    tv_summary = [
        ("Lower Level", "1/7 & 2/7", "Office (006)", "TV-007", "1x: NW-013", "None", "1x: CBL-006", "SW HE"),
        ("Lower Level", "1/7 & 2/7", "Game Room (003) - North Wall TV", "TV-001", "2x: NW-001, NW-002", "1x: VD-001", "1x: CBL-001", "NW/CBL: SW HE | VD: Rack"),
        ("Lower Level", "1/7 & 2/7", "Game Room (003) - Center Display", "TV-002", "2x: NW-003, NW-004", "1x: VD-002", "None", "NW: SW HE | VD: Rack"),
        ("1st Floor", "3/7", "Outdoor Patio / Pergola (by Sport Court 108)", "TV (VD-007)", "2x: NW-014, NW-015", "1x: VD-007", "1x: CBL-007", "SW HE"),
        ("1st Floor", "3/7", "Family Room (105) - West Fireplace (by Kitchen 104)", "TV (VD-003)", "2x: NW-005, NW-006", "1x: VD-003", "1x: CBL-002", "SW HE"),
        ("1st Floor", "3/7", "Living Room (102) - East Fireplace (by Dining 102)", "TV (VD-004)", "2x: NW-007, NW-008", "1x: VD-004", "1x: CBL-003", "NW/CBL: SW HE | VD: AV Closet"),
        ("2nd Floor", "5/7", "Kids' Suite (207) - East Wall", "TV (VD-006)", "2x: NW-011, NW-012", "1x: VD-006", "1x: CBL-005", "NW/CBL: SW HE | VD: AV Closet"),
        ("2nd Floor", "5/7", "Main Bedroom (203) - East Wall Fireplace", "TV (VD-005)", "2x: NW-009, NW-010", "1x: VD-005", "1x: CBL-004", "NW/CBL: SW HE | VD: AV Closet"),
    ]

    for idx, row_vals in enumerate(tv_summary):
        r = 5 + idx
        ws2.row_dimensions[r].height = 24
        full_vals = list(row_vals) + ["", "", ""]
        for c_idx, val in enumerate(full_vals, start=1):
            cell = ws2.cell(row=r, column=c_idx, value=val)
            cell.border = border_all
            cell.font = bold_font if c_idx == 4 else reg_font
            if c_idx == 5:
                cell.fill = cat6_blu_fill
            elif c_idx == 6:
                cell.fill = cat6_yel_fill
            elif c_idx == 7:
                cell.fill = rg6_fill
            if c_idx in (1, 2, 4, 9, 10):
                cell.alignment = center
                if c_idx in (9, 10):
                    cell.font = check_font
            else:
                cell.alignment = left

    dv2 = DataValidation(type="list", formula1='"✓,x,Yes,N/A"', allow_blank=True)
    ws2.add_data_validation(dv2)
    dv2.add("I5:J12")
    ws2.conditional_formatting.add("I5:J12", green_rule)

    ws2.freeze_panes = "A5"
    col_widths_2 = [14, 11, 44, 14, 22, 18, 16, 28, 16, 16, 28]
    for i, w in enumerate(col_widths_2, start=1):
        ws2.column_dimensions[get_column_letter(i)].width = w

    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    build_workbook(r"C:\Users\dav-user1\Desktop\wifi_tool\Cooney_Residence_TV_Wire_Checklist.xlsx")
    build_workbook(r"C:\Users\dav-user1\Downloads\Cooney_Residence_TV_Wire_Checklist.xlsx")

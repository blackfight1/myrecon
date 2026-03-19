/**
 * 数据导出工具
 * 支持 CSV 和 JSON 格式导出
 */

export function exportToCSV<T extends Record<string, unknown>>(
    data: T[],
    columns: { key: keyof T; header: string }[],
    filename: string
): void {
    if (data.length === 0) return;

    const headers = columns.map((c) => c.header);
    const rows = data.map((row) =>
        columns.map((c) => {
            const val = row[c.key];
            if (val === null || val === undefined) return "";
            const str = Array.isArray(val) ? val.join("; ") : String(val);
            // 转义双引号，用双引号包裹含逗号/换行/双引号的字段
            if (str.includes(",") || str.includes("\n") || str.includes('"')) {
                return `"${str.replace(/"/g, '""')}"`;
            }
            return str;
        })
    );

    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const BOM = "\uFEFF"; // UTF-8 BOM for Excel compatibility
    downloadBlob(BOM + csvContent, `${filename}.csv`, "text/csv;charset=utf-8;");
}

export function exportToJSON<T>(data: T[], filename: string): void {
    if (data.length === 0) return;
    const jsonContent = JSON.stringify(data, null, 2);
    downloadBlob(jsonContent, `${filename}.json`, "application/json;charset=utf-8;");
}

function downloadBlob(content: string, filename: string, mimeType: string): void {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type PaginationState,
  type SortingState,
  type Updater
} from "@tanstack/react-table";
import { useMemo, useState } from "react";

interface Props<T extends object> {
  data: T[];
  columns: Array<ColumnDef<T, any>>;
  pageSize?: number;

  manualPagination?: boolean;
  manualSorting?: boolean;
  totalRows?: number;

  pageIndex?: number;
  onPageIndexChange?: (pageIndex: number) => void;
  onPageSizeChange?: (pageSize: number) => void;

  sorting?: SortingState;
  onSortingChange?: (sorting: SortingState) => void;
}

function applyUpdater<T>(updater: Updater<T>, prev: T): T {
  return typeof updater === "function" ? (updater as (old: T) => T)(prev) : updater;
}

export function DataTable<T extends object>({
  data,
  columns,
  pageSize = 25,
  manualPagination = false,
  manualSorting = false,
  totalRows,
  pageIndex,
  onPageIndexChange,
  onPageSizeChange,
  sorting,
  onSortingChange
}: Props<T>) {
  const [internalSorting, setInternalSorting] = useState<SortingState>([]);
  const [internalPagination, setInternalPagination] = useState<PaginationState>({ pageIndex: 0, pageSize });

  const sortingState = sorting ?? internalSorting;
  const paginationState: PaginationState = {
    pageIndex: pageIndex ?? internalPagination.pageIndex,
    pageSize: internalPagination.pageSize
  };

  const handleSortingChange = (updater: Updater<SortingState>) => {
    const next = applyUpdater(updater, sortingState);
    if (onSortingChange) {
      onSortingChange(next);
    } else {
      setInternalSorting(next);
    }
  };

  const handlePaginationChange = (updater: Updater<PaginationState>) => {
    const next = applyUpdater(updater, paginationState);
    if (onPageIndexChange) onPageIndexChange(next.pageIndex);
    if (onPageSizeChange && next.pageSize !== paginationState.pageSize) onPageSizeChange(next.pageSize);
    setInternalPagination(next);
  };

  const computedTotalRows = totalRows ?? data.length;
  const computedPageCount = manualPagination
    ? Math.max(1, Math.ceil(computedTotalRows / Math.max(1, paginationState.pageSize)))
    : undefined;

  const table = useReactTable({
    data,
    columns,
    state: { sorting: sortingState, pagination: paginationState },
    onSortingChange: handleSortingChange,
    onPaginationChange: handlePaginationChange,
    getCoreRowModel: getCoreRowModel(),
    ...(manualSorting ? {} : { getSortedRowModel: getSortedRowModel() }),
    ...(manualPagination ? {} : { getPaginationRowModel: getPaginationRowModel() }),
    manualSorting,
    manualPagination,
    pageCount: computedPageCount,
    initialState: { pagination: { pageSize } }
  });

  const pageCount = manualPagination ? (computedPageCount ?? 1) : table.getPageCount();
  const currentPage = paginationState.pageIndex;

  const showingStart = useMemo(() => {
    if (computedTotalRows === 0) return 0;
    return currentPage * paginationState.pageSize + 1;
  }, [computedTotalRows, currentPage, paginationState.pageSize]);

  const showingEnd = useMemo(() => {
    if (computedTotalRows === 0) return 0;
    return Math.min((currentPage + 1) * paginationState.pageSize, computedTotalRows);
  }, [computedTotalRows, currentPage, paginationState.pageSize]);

  const canPrevious = currentPage > 0;
  const canNext = currentPage + 1 < pageCount;

  return (
    <>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((header) => (
                  <th key={header.id} onClick={header.column.getToggleSortingHandler()}>
                    {header.isPlaceholder ? null : (
                      <>
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        <span className="th-sort-indicator">
                          {header.column.getIsSorted() === "asc"
                            ? "↑"
                            : header.column.getIsSorted() === "desc"
                              ? "↓"
                              : ""}
                        </span>
                      </>
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>
                  <div className="empty-state">No records found</div>
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {pageCount > 1 && (
        <div className="pagination">
          <span>
            Showing {showingStart}–{showingEnd} of {computedTotalRows}
          </span>
          <div className="pagination-controls">
            <button className="pagination-btn" onClick={() => handlePaginationChange({ ...paginationState, pageIndex: 0 })} disabled={!canPrevious}>
              «
            </button>
            <button className="pagination-btn" onClick={() => handlePaginationChange({ ...paginationState, pageIndex: Math.max(0, currentPage - 1) })} disabled={!canPrevious}>
              ‹
            </button>
            <span style={{ padding: "0 8px", fontSize: 12, color: "var(--text-secondary)" }}>
              {currentPage + 1} / {pageCount}
            </span>
            <button className="pagination-btn" onClick={() => handlePaginationChange({ ...paginationState, pageIndex: Math.min(pageCount - 1, currentPage + 1) })} disabled={!canNext}>
              ›
            </button>
            <button className="pagination-btn" onClick={() => handlePaginationChange({ ...paginationState, pageIndex: Math.max(0, pageCount - 1) })} disabled={!canNext}>
              »
            </button>
            <select
              className="page-size-select"
              value={paginationState.pageSize}
              onChange={(e) => handlePaginationChange({ pageIndex: 0, pageSize: Number(e.target.value) })}
            >
              {[25, 50, 100].map((size) => (
                <option key={size} value={size}>
                  {size}/page
                </option>
              ))}
            </select>
          </div>
        </div>
      )}
    </>
  );
}

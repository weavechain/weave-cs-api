namespace weaveapi;

public class Filter
{
    public static Filter NONE = new Filter(null, null, null, null, null, null);
    public FilterOp op { get; set; }

    public Dictionary<string, Direction> order { get; set; }

    public int? limit { get; set; }

    public List<string> collapsing { get; set; }

    public List<string> columns { get; set; }

    public FilterOp postFilterOp { get; set; }

    public Filter(
        FilterOp op,
        Dictionary<string, Direction> order,
        int? limit,
        List<string> collapsing,
        List<string> columns,
        FilterOp postFilterOp
    )
    {
        this.op = op;
        this.order = order;
        this.limit = limit;
        this.collapsing = collapsing;
        this.columns = columns;
        this.postFilterOp = postFilterOp;
    }

    public class FilterOp
    {
        public Operation operation { get; set; }

        public FilterOp left { get; set; }

        public FilterOp right { get; set; }

        public object value { get; set; }

        public FilterOp(Operation operation, FilterOp left, FilterOp right, object value)
        {
            this.operation = operation;
            this.left = left;
            this.right = right;
            this.value = value;
        }

        public static FilterOp Field(String field)
        {
            return new FilterOp(Operation.field, null, null, field);
        }

        public static FilterOp Value(Object value)
        {
            return new FilterOp(Operation.value, null, null, value);
        }

        public static FilterOp Eq(String field, Object value)
        {
            return new FilterOp(Operation.eq, Field(field), Value(value), null);
        }

        public static FilterOp Neq(String field, Object value)
        {
            return new FilterOp(Operation.neq, Field(field), Value(value), null);
        }

        public static FilterOp In(String field, List<Object> values)
        {
            return new FilterOp(Operation.@in, Field(field), Value(values), null);
        }

        public static FilterOp Notin(String field, List<Object> values)
        {
            return new FilterOp(Operation.notin, Field(field), Value(values), null);
        }

        public static FilterOp Gt(String field, Object value)
        {
            return new FilterOp(Operation.gt, Field(field), Value(value), null);
        }

        public static FilterOp Gte(String field, Object value)
        {
            return new FilterOp(Operation.gte, Field(field), Value(value), null);
        }

        public static FilterOp Lt(String field, Object value)
        {
            return new FilterOp(Operation.lt, Field(field), Value(value), null);
        }

        public static FilterOp Lte(String field, Object value)
        {
            return new FilterOp(Operation.lte, Field(field), Value(value), null);
        }

        public static FilterOp And(FilterOp expr1, FilterOp expr2)
        {
            return new FilterOp(Operation.and, expr1, expr2, null);
        }

        public static FilterOp And(FilterOp expr1, FilterOp expr2, List<FilterOp> expressions)
        {
            FilterOp res = new FilterOp(Operation.and, expr1, expr2, null);
            foreach (FilterOp expr in expressions)
            {
                res = new FilterOp(Operation.and, res, expr, null);
            }
            return res;
        }

        public static FilterOp Or(FilterOp expr1, FilterOp expr2)
        {
            return new FilterOp(Operation.or, expr1, expr2, null);
        }

        public static FilterOp Or(FilterOp expr1, FilterOp expr2, List<FilterOp> expressions)
        {
            FilterOp res = new FilterOp(Operation.or, expr1, expr2, null);
            foreach (FilterOp expr in expressions)
            {
                res = new FilterOp(Operation.or, res, expr, null);
            }
            return res;
        }

        public static FilterOp Not(FilterOp expr)
        {
            return new FilterOp(Operation.not, expr, null, null);
        }
    }

    public enum Operation
    {
        eq,

        neq,

        @in,

        notin,

        gt,

        gte,

        lt,

        lte,

        not,

        and,

        or,

        contains,

        field,

        value
    }

    public enum Direction
    {
        ASC,
        DESC
    }
}

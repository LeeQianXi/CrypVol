using System.Collections;
using System.Diagnostics.Contracts;

namespace CrypVol.Lib;

public static partial class Extension
{
    public static IEnumerable<T> Concat<T>(params IEnumerable[] enumerables)
    {
        return enumerables.NotNull().SelectMany(enumerable => enumerable.OfType<T>());
    }

    private static void OrderByDependenciesVisit<T>(T item, HashSet<T> visited, List<T> sorted,
        Func<T, IEnumerable<T>> getDependencies, bool throwOnCycle)
    {
        if (visited.Add(item))
        {
            foreach (var dependency in getDependencies(item))
                OrderByDependenciesVisit(dependency, visited, sorted, getDependencies, throwOnCycle);

            sorted.Add(item);
        }
        else
        {
            if (throwOnCycle && !sorted.Contains(item)) throw new InvalidOperationException("Cyclic dependency.");
        }
    }

    extension<T>(T obj)
    {
        public IEnumerable<T> Yield()
        {
            yield return obj;
        }
    }

    private static class HashSetPool<T>
    {
        private static readonly object _lock = new();
        private static readonly Stack<HashSet<T>> _avaliable = new();
        private static readonly HashSet<HashSet<T>> _inUse = [];

        public static HashSet<T> Acquire()
        {
            lock (_lock)
            {
                if (_avaliable.Count == 0) _avaliable.Push([]);

                var hashSet = _avaliable.Pop();

                _inUse.Add(hashSet);

                return hashSet;
            }
        }

        public static void Release(HashSet<T> hashSet)
        {
            lock (_lock)
            {
                if (!_inUse.Remove(hashSet))
                    throw new ArgumentException("The hash set to _avaliable is not in use by the pool.",
                        nameof(hashSet));

                hashSet.Clear();

                _avaliable.Push(hashSet);
            }
        }
    }

    extension<T>(IEnumerable<T> enumerable)
    {
        [Pure]
        public IEnumerable<T> DistinctBy<TKey>(Func<T, TKey> property)
        {
            return enumerable.GroupBy(property).Select(x => x.First());
        }

        public IEnumerable<T> NotNull()
        {
            return enumerable.Where(i => i != null);
        }

        public HashSet<T> ToHashSet()
        {
            return [..enumerable];
        }
        // NETUP: Replace with IReadOnlyCollection, IReadOnlyList

        public ICollection<T> AsReadOnlyCollection()
        {
            if (enumerable is ICollection<T> collection) return collection;
            return enumerable.ToList().AsReadOnly();
        }

        public IList<T> AsReadOnlyList()
        {
            if (enumerable is IList<T> list) return list;
            return enumerable.ToList().AsReadOnly();
        }

        public IEnumerable<T> Flatten(Func<T, IEnumerable<T>> childrenSelector)
        {
            return enumerable.Aggregate(enumerable,
                (current, element) => current.Concat(childrenSelector(element).Flatten(childrenSelector)));
        }

        public IEnumerable<T> OrderByDependencies(Func<T, IEnumerable<T>> getDependencies, bool throwOnCycle = true)
        {
            var sorted = new List<T>();
            var visited = HashSetPool<T>.Acquire();
            foreach (var item in enumerable)
                OrderByDependenciesVisit(item, visited, sorted, getDependencies, throwOnCycle);
            HashSetPool<T>.Release(visited);
            return sorted;
        }

        public IEnumerable<T> Catch(Action<Exception> @catch)
        {
            ArgumentNullException.ThrowIfNull(enumerable);
            using var enumerator = enumerable.GetEnumerator();
            bool success;
            do
            {
                try
                {
                    success = enumerator.MoveNext();
                }
                catch (OperationCanceledException)
                {
                    yield break;
                }
                catch (Exception ex)
                {
                    @catch?.Invoke(ex);
                    success = false;
                }

                if (success) yield return enumerator.Current;
            } while (success);
        }

        public IEnumerable<T> Catch(ICollection<Exception> exceptions)
        {
            ArgumentNullException.ThrowIfNull(exceptions);
            return enumerable.Catch(exceptions.Add);
        }

        public void Foreach(Action<T> action)
        {
            foreach (var item in enumerable)
                action(item);
        }

        public void Foreach(Action<int, T> action)
        {
            var index = 0;
            foreach (var item in enumerable)
                action(index++, item);
        }
    }

    extension<T>(ICollection<T> collection)
    {
        public void AddRange(IEnumerable<T> items)
        {
            foreach (var item in items) collection.Add(item);
        }
    }

    extension(IList list)
    {
        public void AddRange(IEnumerable items)
        {
            foreach (var item in items) list.Add(item);
        }
    }


    extension<T>(IEnumerable<IEnumerable<T>> groups)
    {
        public IEnumerable<T> IntersectAll()
        {
            HashSet<T>? hashSet = null;
            foreach (var group in groups)
                if (hashSet == null)
                    hashSet = [..group];
                else
                    hashSet.IntersectWith(group);
            return hashSet?.AsEnumerable() ?? [];
        }
    }

    extension<T>(IEnumerable<T> source)
        where T : notnull
    {
        public IEnumerable<T> OrderByDependers(Func<T, IEnumerable<T>> getDependers, bool throwOnCycle = true)
        {
            // TODO: Optimize, or use another algorithm (Kahn's?)
            // Convert dependers to dependencies
            var dependencies = new Dictionary<T, HashSet<T>>();
            foreach (var dependency in source)
            foreach (var depender in getDependers(dependency))
            {
                if (!dependencies.TryGetValue(depender, out var value))
                {
                    value = [];
                    dependencies.Add(depender, value);
                }

                value.Add(dependency);
            }

            return source.OrderByDependencies(
                depender => dependencies.TryGetValue(depender, out var expression) ? expression : [], throwOnCycle);
        }
    }
}
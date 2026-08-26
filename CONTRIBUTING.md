# 🤝 Contributing to Encrypted SQLite System

We welcome contributions, bug fixes, and performance improvements!

---

## 🛠️ Development Setup

1. **Fork and Clone the repository**:
   ```bash
   git clone https://github.com/Yannis-A-D/encrypted_sqlite_system.git
   cd encrypted_sqlite_system
   ```

2. **Install development dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-cov
   ```

3. **Run the test suite**:
   ```bash
   pytest -v
   ```

4. **Run the performance benchmark**:
   ```bash
   python benchmarks/benchmark.py 1000
   ```

---

## 📜 Pull Request Guidelines

1. Ensure all 13+ unit tests pass with `pytest`.
2. Add new unit tests for any new features or bug fixes.
3. Keep code compliant with PEP 8 and include type hints where possible.
4. Ensure no secret keys or database files (`.db`, `secret.key`) are committed.

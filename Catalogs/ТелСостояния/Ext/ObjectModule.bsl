﻿Процедура ОбработкаПроверкиЗаполнения(Отказ,ПроверяемыеРеквизиты)

// Нормализация реквизитов
//-------------------------------------------------------------------------------------------------
	ЭтотОбъект.СерверныйКод = ВРег(СокрЛП(ЭтотОбъект.СерверныйКод));
	ЭтотОбъект.Интерфейс = ВРег(СокрЛП(ЭтотОбъект.Интерфейс));
	ЭтотОбъект.Наименование = СокрЛП(ЭтотОбъект.Наименование);

// Проверка на дублирование по Наименованию
//-------------------------------------------------------------------------------------------------
	ТекстЗапроса = "
	|SELECT	COUNT(*) AS Всего
	|FROM	Справочник.ТелСостояния
	|WHERE	(Ссылка <> &ЭтотОбъект) И (Наименование = &Наименование)";

	Запрос = Новый Запрос;
	Запрос.Текст = ТекстЗапроса;
	Запрос.УстановитьПараметр("ЭтотОбъект",ЭтотОбъект.Ссылка);
	Запрос.УстановитьПараметр("Наименование",ЭтотОбъект.Наименование);
	Результат = Запрос.Выполнить().Выбрать();

	Если (Результат.Следующий()) И (Результат.Всего > 0) Тогда
		ТекстСообщения = "Состояние с наименованием """ + СокрЛП(ЭтотОбъект.Наименование) + """ уже присутствует в справочнике";
		Сообщить(ТекстСообщения);
		Отказ = Истина;
		Возврат;
	КонецЕсли;
КонецПроцедуры

Процедура ПередЗаписью(Отказ)
	Если (НЕ ЭтотОбъект.ПроверитьЗаполнение()) Тогда
		Отказ = Истина;
		Возврат;
	КонецЕсли;
КонецПроцедуры
